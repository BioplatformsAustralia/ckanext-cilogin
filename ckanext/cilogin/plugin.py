import logging

import ckan.model as model
import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
from ckan.lib.api_token import decode, encode
from ckanext.saml2auth.interfaces import ISaml2Auth

from ckanext.cilogin import helpers as helpers

log = logging.getLogger(__name__)


class CiloginPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(ISaml2Auth, inherit=True)
    

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_public_directory(config_, "public")
        tk.add_resource("assets", "cilogin")


    def after_saml2_login(self, resp, saml_attributes):
        if tk.g.userobj.email in saml_attributes.get("mail"):
            # check if there is a API token for this user
            user = tk.get_action('user_show')({}, {'id':  tk.g.user })
            tokens = tk.get_action(u"api_token_list")(
                {u"ignore_auth": True}, {u"user": user.get("name")})
            token = None
            if not tokens or "ci_login" not in [token.get("name") for token in tokens]:
                token =_create_user_token(user)
            # else:
            #     for token in tokens:
            #         if token.get("name") != "ci_login":
            #             token = _create_user_token(user)
            
            
            if token:
                helpers.process_token(user, token)
        
            # Update memberships
            _update_memberships(user, saml_attributes)
        return resp

def _create_user_token(user):
    token = tk.get_action(u"api_token_create")(
        {u"ignore_auth": True},
        {u"user": user.get("name"), u"name": "ci_login"},
    )
    return token.get('token')

def _update_memberships(user, saml_attributes):
    context = {
            "model": model,
            "user": user.get("name"),
            "ignore_auth": True

            }
    memberships = saml_attributes.get('isMemberOf',[])
    
    add_membership(context, user, memberships)
    remove_membership(context, user, memberships)



def add_membership(context, user, memberships):
    for membership in memberships:
        if 'bpadp' in membership:
            prefix, group, role = membership.split(':')
            group_dict = None
            try:
                group_dict = tk.get_action('organization_show')(context,{"id": group})
            except Exception as e:
                log.error("Error getting group")
                log.error(e)
            if group_dict:
                try:
                    data_dict = {
                        "id": group_dict.get('name'),
                        'username': user.get("name"),
                        'role':role.lower()
                        }
                    log.info("Adding user to group")
                    result = tk.get_action('organization_member_create')(context,data_dict)
                    log.info(result)
                except Exception as e:
                    log.error("Error adding user to group")
                    log.error(e)
        else:
            log.info("Not a BPADP group in the membership list")

def remove_membership(context, user, memberships):
    # Get all groups the user is a member of
    groups = []
    site_user = tk.get_action('get_site_user')({'ignore_auth': True},{})
    for membership in memberships:
        if 'bpadp' in membership:
            prefix, group, role = membership.split(':')
            groups.append(group)
    user_groups = tk.get_action('organization_list_for_user')(context,{"id": user.get("name")})
    for group in user_groups:
        if group.get('name') not in groups:
            try:
                data_dict = {
                    "id": group.get('name'),
                    'username': user.get("name"),
                    }
                log.info("Removing user from group")
                result = tk.get_action('organization_member_delete')({'user': site_user['name']},data_dict)
                log.info(result)
            except Exception as e:
                log.error("Error removing user from group")
                log.error(e)
        else:
            log.info("User is a member of this group")