import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
from ckanext.saml2auth.interfaces import ISaml2Auth

class CiloginPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(ISaml2Auth, inherit=True)
    

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_public_directory(config_, "public")
        tk.add_resource("assets", "cilogin")

    
def after_saml2_login(self, resp, saml_attributes):
    if resp.get('user'):
        # check if there is a API token for this user
        user = tk.get_action('user_show')({}, {'id':  resp.get('user')})
        tokens = tk.get_action(u"api_token_list")(
            {u"ignore_auth": True}, {u"user": user.get("name")})

        for token in tokens:
            if token.get("name") != "ci_login":
                token = tk.get_action(u"api_token_create")({u"ignore_auth": True}, 
                {u"user": user.get("name"), u"name": "ci_login"})
            resp["token"] = token.get("token")
    return resp