from flask import Flask, request, jsonify
import ldap
from os import getenv

app = Flask(__name__)

ldap_server = getenv('LDAP_SERVER', 'ldap://localhost:389')

def ldap_verify(ldap_base_dn, ldap_username, ldap_password, ldap_group):

    # LDAP Bind DN for Authentik login
    ldap_bind_dn = f"cn={ldap_username},ou=users,{ldap_base_dn}"

    # LDAP group DN for Authentik LDAP search
    ldap_group_dn = f"cn={ldap_group},ou=groups,{ldap_base_dn}"

    # Initialize the LDAP connection
    conn = ldap.initialize(ldap_server)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.simple_bind_s(ldap_bind_dn, ldap_password)

    # Search for the user in the specified group
    search_filter = f"(&(cn={ldap_username})(memberOf={ldap_group_dn}))"
    result = conn.search_s(ldap_base_dn, ldap.SCOPE_SUBTREE, search_filter)

    if result:
        log = f"User {ldap_username} authenticated successfully and found in group {ldap_group}."
        return {"success": True, "log": log}
    else:
        log = f"User {ldap_username} authenticated successfully but not found in group {ldap_group}."
        return {"success": False, "log": log}

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    ldap_base_dn = data.get('ldap_base_dn')
    ldap_username = data.get('ldap_username')
    ldap_password = data.get('ldap_password')
    ldap_group = data.get('ldap_group')

    result = ldap_verify(ldap_base_dn, ldap_username, ldap_password, ldap_group)
    return jsonify(result)
