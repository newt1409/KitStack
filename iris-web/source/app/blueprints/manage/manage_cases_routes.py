#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2021 - DFIR-IRIS Airbus CyberSecurity (SAS)
#  contact@dfir-iris.org - ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import logging as log
import marshmallow
# IMPORTS ------------------------------------------------
import os
import traceback
import urllib.parse
from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_login import current_user
from flask_wtf import FlaskForm

from app import db
from app.datamgmt.case.case_db import get_case
from app.datamgmt.case.case_db import register_case_protagonists
from app.datamgmt.case.case_db import save_case_tags
from app.datamgmt.iris_engine.modules_db import get_pipelines_args_from_name
from app.datamgmt.iris_engine.modules_db import iris_module_exists
from app.datamgmt.manage.manage_attribute_db import get_default_custom_attributes
from app.datamgmt.manage.manage_cases_db import close_case
from app.datamgmt.manage.manage_cases_db import delete_case
from app.datamgmt.manage.manage_cases_db import get_case_details_rt
from app.datamgmt.manage.manage_cases_db import get_case_protagonists
from app.datamgmt.manage.manage_cases_db import list_cases_dict
from app.datamgmt.manage.manage_cases_db import reopen_case
from app.datamgmt.manage.manage_users_db import add_case_access_to_user
from app.datamgmt.manage.manage_users_db import get_user_organisations
from app.forms import AddCaseForm
from app.iris_engine.access_control.utils import ac_fast_check_current_user_has_case_access
from app.iris_engine.access_control.utils import ac_fast_check_user_has_case_access
from app.iris_engine.access_control.utils import ac_set_new_case_access
from app.iris_engine.module_handler.module_handler import call_modules_hook
from app.iris_engine.module_handler.module_handler import configure_module_on_init
from app.iris_engine.module_handler.module_handler import instantiate_module_from_name
from app.iris_engine.tasker.tasks import task_case_update
from app.iris_engine.utils.common import build_upload_path
from app.iris_engine.utils.tracker import track_activity
from app.models.authorization import CaseAccessLevel
from app.models.authorization import Permissions
from app.models.models import Client
from app.schema.marshables import CaseSchema
from app.util import ac_api_case_requires
from app.util import ac_api_requires
from app.util import ac_api_return_access_denied
from app.util import ac_case_requires
from app.util import ac_requires
from app.util import response_error
from app.util import response_success

manage_cases_blueprint = Blueprint('manage_case',
                                   __name__,
                                   template_folder='templates')


# CONTENT ------------------------------------------------
@manage_cases_blueprint.route('/manage/cases', methods=['GET'])
@ac_requires(Permissions.standard_user)
def manage_index_cases(caseid, url_redir):
    if url_redir:
        return redirect(url_for('manage_case.manage_index_cases', cid=caseid))

    form = AddCaseForm()
    # Fill select form field customer with the available customers in DB
    form.case_customer.choices = [(c.client_id , c.name) for c in
                                  Client.query.order_by(Client.name)]

    form.case_organisations.choices = [(org['org_id'], org['org_name']) for org in get_user_organisations(current_user.id)]

    attributes = get_default_custom_attributes('case')

    return render_template('manage_cases.html', form=form, attributes=attributes)


@manage_cases_blueprint.route('/manage/cases/details/<int:cur_id>', methods=['GET'])
@ac_case_requires()
def details_case(cur_id, caseid, url_redir):
    if url_redir:
        return response_error("Invalid request")

    if not ac_fast_check_user_has_case_access(current_user.id, cur_id, [CaseAccessLevel.read_only,
                                                                        CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=cur_id)

    res = get_case_details_rt(cur_id)
    form = FlaskForm()

    if res:
        return render_template("modal_case_info_from_case.html", data=res, form=form, protagnists=None)

    else:
        return response_error("Unknown case")


@manage_cases_blueprint.route('/case/details/<int:cur_id>', methods=['GET'])
@ac_case_requires()
def details_case_from_case(cur_id, caseid, url_redir):
    if url_redir:
        return response_error("Invalid request")

    if not ac_fast_check_current_user_has_case_access(cur_id, [CaseAccessLevel.read_only, CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=cur_id)

    res = get_case_details_rt(cur_id)

    protagonists = get_case_protagonists(cur_id)

    form = FlaskForm()

    if res:
        return render_template("modal_case_info_from_case.html", data=res, form=form, protagonists=protagonists)

    else:
        return response_error("Unknown case")


@manage_cases_blueprint.route('/manage/cases/<int:cur_id>', methods=['GET'])
@ac_api_case_requires()
def get_case_api(cur_id, caseid):

    if not ac_fast_check_current_user_has_case_access(cur_id, [CaseAccessLevel.read_only, CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=cur_id)

    res = get_case_details_rt(cur_id)
    if res:
        return response_success(data=res._asdict())

    return response_error(f'Case ID {cur_id} not found')


@manage_cases_blueprint.route('/manage/cases/delete/<int:cur_id>', methods=['POST'])
@ac_api_requires(Permissions.standard_user)
def api_delete_case(cur_id, caseid):

    if not ac_fast_check_current_user_has_case_access(cur_id, [CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=cur_id)

    if cur_id == 1:
        track_activity("tried to delete case {}, but case is the primary case".format(cur_id),
                       caseid=caseid, ctx_less=True)

        return response_error("Cannot delete a primary case to keep consistency")

    else:
        try:
            call_modules_hook('on_preload_case_delete', data=cur_id, caseid=caseid)
            if delete_case(case_id=cur_id):

                call_modules_hook('on_postload_case_delete', data=cur_id, caseid=caseid)

                track_activity("case {} deleted successfully".format(cur_id), caseid=1, ctx_less=True)
                return response_success("Case successfully deleted")

            else:
                track_activity("tried to delete case {}, but it doesn't exist".format(cur_id),
                               caseid=caseid, ctx_less=True)

                return response_error("Tried to delete a non-existing case")

        except Exception as e:
            return response_error("Cannot delete a non empty case. {}".format(e))


@manage_cases_blueprint.route('/manage/cases/reopen/<int:cur_id>', methods=['GET'])
@ac_api_requires(Permissions.standard_user)
def api_reopen_case(cur_id, caseid):

    if not ac_fast_check_current_user_has_case_access(cur_id, [CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=cur_id)

    if not cur_id:
        return response_error("No case ID provided")

    res = reopen_case(cur_id)
    if not res:
        return response_error("Tried to reopen an non-existing case")

    track_activity("reopened case ID {}".format(cur_id), caseid=caseid, ctx_less=True)
    case_schema = CaseSchema()

    return response_success("Case reopened successfully", data=case_schema.dump(res))


@manage_cases_blueprint.route('/manage/cases/close/<int:cur_id>', methods=['GET'])
@ac_api_requires(Permissions.standard_user)
def api_case_close(cur_id, caseid):
    if not ac_fast_check_current_user_has_case_access(cur_id, [CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=cur_id)

    if not cur_id:
        return response_error("No case ID provided")

    res = close_case(cur_id)
    if not res:
        return response_error("Tried to close an non-existing case")

    track_activity("closed case ID {}".format(cur_id), caseid=caseid, ctx_less=True)
    case_schema = CaseSchema()

    return response_success("Case closed successfully", data=case_schema.dump(res))


@manage_cases_blueprint.route('/manage/cases/add', methods=['POST'])
@ac_api_requires(Permissions.standard_user)
def api_add_case(caseid):

    case_schema = CaseSchema()

    try:

        request_data = call_modules_hook('on_preload_case_create', data=request.get_json(), caseid=caseid)
        case = case_schema.load(request_data)

        case.save()

        ac_set_new_case_access(None, case.case_id)

        case = call_modules_hook('on_postload_case_create', data=case, caseid=caseid)

        track_activity("New case {case_name} created".format(case_name=case.name), caseid=caseid, ctx_less=True)

    except marshmallow.exceptions.ValidationError as e:
        return response_error(msg="Data error", data=e.messages, status=400)

    except Exception as e:
        log.error(e.__str__())
        log.error(traceback.format_exc())
        return response_error(msg="Error creating case", data=e.__str__(), status=400)

    return response_success(msg='Case created', data=case_schema.dump(case))


@manage_cases_blueprint.route('/manage/cases/list', methods=['GET'])
@ac_api_requires(Permissions.standard_user)
def api_list_case(caseid):

    data = list_cases_dict(current_user.id)

    return response_success("", data=data)


@manage_cases_blueprint.route('/manage/cases/update', methods=['POST'])
@ac_api_requires(Permissions.standard_user)
def update_case_info(caseid):

    if not ac_fast_check_current_user_has_case_access(caseid, [CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=caseid)

    # case update request. The files should have already arrived with the request upload_files
    case_schema = CaseSchema()

    case_i = get_case(caseid)
    if not case_i:
        return response_error("Case not found")

    try:

        request_data = request.get_json()

        request_data['case_name'] = f"#{case_i.case_id} - {request_data['case_name']}"
        request_data['case_customer'] = case_i.client_id

        case = case_schema.load(request_data, instance=case_i, partial=True)

        db.session.commit()

        register_case_protagonists(case.case_id, request_data['protagonists'])
        save_case_tags(request_data['case_tags'], case_i.case_id)

        track_activity("Case updated {case_name}".format(case_name=case.name), caseid=caseid)

    except marshmallow.exceptions.ValidationError as e:
        return response_error(msg="Data error", data=e.messages, status=400)
    except Exception as e:
        log.error(e.__str__())
        log.error(traceback.format_exc())
        return response_error(msg="Error creating case", data=e.__str__(), status=400)

    return response_success(msg='Case updated', data=case_schema.dump(case))


@manage_cases_blueprint.route('/manage/cases/trigger-pipeline', methods=['POST'])
@ac_api_requires(Permissions.standard_user)
def update_case_files(caseid):
    if not ac_fast_check_current_user_has_case_access(caseid, [CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=caseid)

    # case update request. The files should have already arrived with the request upload_files
    try:
        # Create the update task
        jsdata = request.get_json()
        if not jsdata:
            return response_error('Not a JSON content', status=400)

        pipeline = jsdata.get('pipeline')

        try:
            pipeline_mod = pipeline.split("-")[0]
            pipeline_name = pipeline.split("-")[1]
        except Exception as e:
            log.error(e.__str__())
            return response_error('Malformed request', status=400)

        ppl_config = get_pipelines_args_from_name(pipeline_mod)
        if not ppl_config:
            return response_error('Malformed request', status=400)

        pl_args = ppl_config['pipeline_args']
        pipeline_args = {}
        for argi in pl_args:

            arg = argi[0]
            fetch_arg = jsdata.get('args_' + arg)

            if argi[1] == 'required' and (not fetch_arg or fetch_arg == ""):
                return response_error("Required arguments are not set")

            if fetch_arg:
                pipeline_args[arg] = fetch_arg

            else:
                pipeline_args[arg] = None

        status = task_case_update(
            module=pipeline_mod,
            pipeline=pipeline_name,
            pipeline_args=pipeline_args,
            caseid=caseid)

        if status.is_success():
            # The job has been created, so return. The progress can be followed on the dashboard
            return response_success("Case task created")

        else:
            # We got some errors and cannot continue
            return response_error(status.get_message(), data=status.get_data())

    except Exception as e:
        traceback.print_exc()
        return response_error('Fail to update case', data=traceback.print_exc())


@manage_cases_blueprint.route('/manage/cases/upload_files', methods=['POST'])
@ac_api_requires(Permissions.standard_user)
def manage_cases_uploadfiles(caseid):
    """
    Handles the entire the case management, i.e creation, update, list and files imports
    :param path: Path within the URL
    :return: Depends on the path, either a page a JSON
    """
    if not ac_fast_check_current_user_has_case_access(caseid, [CaseAccessLevel.full_access]):
        return ac_api_return_access_denied(caseid=caseid)

    # Files uploads of a case. Get the files, create the folder tree
    # The request "add" will start the check + import of the files.
    f = request.files.get('file')

    is_update = request.form.get('is_update', type=str)
    pipeline = request.form.get('pipeline', '', type=str)

    try:
        pipeline_mod = pipeline.split("-")[0]
    except Exception as e:
        log.error(e.__str__())
        return response_error('Malformed request', status=400)

    if not iris_module_exists(pipeline_mod):
        return response_error('Missing pipeline', status=400)

    mod, _ = instantiate_module_from_name(pipeline_mod)
    status = configure_module_on_init(mod)
    if status.is_failure():
        return response_error("Path for upload {} is not built ! Unreachable pipeline".format(
            os.path.join(f.filename)), status=400)

    case_customer = None
    case_name = None

    if is_update == "true":
        case = get_case(caseid)

        if case:
            case_name = case.name
            case_customer = case.client.name

    else:
        case_name = urllib.parse.quote(request.form.get('case_name', '', type=str), safe='')
        case_customer = request.form.get('case_customer', type=str)

    fpath = build_upload_path(case_customer=case_customer,
                              case_name=urllib.parse.unquote(case_name),
                              module=pipeline_mod,
                              create=is_update
                              )

    status = mod.pipeline_files_upload(fpath, f, case_customer, case_name, is_update)

    if status.is_success():
        return response_success(status.get_message())

    return response_error(status.get_message(), status=400)