import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
from ckan.lib.api_token import decode, encode
from ckanext.saml2auth.interfaces import ISaml2Auth

from ckanext.cilogin import helpers as helpers

class CiloginPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(ISaml2Auth, inherit=True)
    

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_public_directory(config_, "public")
        tk.add_resource("assets", "cilogin")

    # ISaml2Auth 
    def after_saml2_login(self, resp, saml_attributes):
        if tk.g.userobj.email in saml_attributes.get("mail"):
            # check if there is a API token for this user
            user = tk.get_action('user_show')({}, {'id':  tk.g.user })
            tokens = tk.get_action(u"api_token_list")(
                {u"ignore_auth": True}, {u"user": user.get("name")})
            token = None
            if not tokens:
                token =_create_user_token(user)
            else:
                for token in tokens:
                    if token.get("name") != "ci_login":
                        token = _create_user_token(user)
            
            
            if token:
                helpers.process_token(user, token)
        return resp

def _create_user_token(user):
    token = tk.get_action(u"api_token_create")(
        {u"ignore_auth": True},
        {u"user": user.get("name"), u"name": "ci_login"},
    )
    return token.get('token')