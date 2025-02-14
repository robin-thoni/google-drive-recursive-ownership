#!/usr/bin/python

import argparse
import sys
import pprint
import os

import six
import httplib2
import googleapiclient.discovery
import googleapiclient.http
import googleapiclient.errors
import oauth2client.client

import urllib.parse
import threading

from http.server import BaseHTTPRequestHandler, HTTPServer


class Batch:
    def __init__(self, service):
        self.service = service
        self.batch = service.new_batch_http_request(callback=self._cb)
        self.results = []

    def add(self, request):
        self.batch.add(request)
        if len(self.batch._order) >= 100:
            self.execute()
    
    def _cb(self, request_id, response, exception):
        if exception:
            print('An error occurred: {}'.format(exception))
        else:
            self.results.append(response)

    def execute(self):
        if self.batch._order:
            self.batch.execute()
            self.batch = self.service.new_batch_http_request(callback=self._cb)

class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse the URL to extract the authorization code
        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if "code" in query_params:
            auth_code = query_params["code"][0]
            print(f"Received OAuth Code: {auth_code}")
            
            # Send a response to the user
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Authentication successful! You can close this window.")
            
            # Shut down the server after receiving the code
            self.server.auth_code = auth_code
            threading.Thread(target=self.server.shutdown).start()
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing authorization code.")

def start_server(port=8080):
    server_address = ("", port)
    httpd = HTTPServer(server_address, OAuthHandler)
    print(f"Listening on port {port} for OAuth response...")
    httpd.auth_code = None
    httpd.serve_forever()
    return httpd.auth_code

def get_credentials(auth):

    if auth != 'interactive':
        with open(auth, "r") as token:
            credentials = oauth2client.client.OAuth2Credentials.from_json(token.read())
    else:
        flow = oauth2client.client.flow_from_clientsecrets('client_secrets.json', 'https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email')
        flow.redirect_uri = "http://localhost:8080"
        authorize_url = flow.step1_get_authorize_url()
        print('Use this link for authorization: {}'.format(authorize_url))
        code = start_server()
        credentials = flow.step2_exchange(code)

    return credentials

def get_permission_id_for_email(service, email):
    try:
        id_resp = service.permissions().getIdForEmail(email=email).execute()
        return id_resp['id']
    except googleapiclient.errors.HttpError as e:
        print('An error occured: {}'.format(e))

def show_info(service, drive_item, prefix, permission_id):
    try:
        print(os.path.join(prefix, drive_item['title']))
        print('Would set new owner to {}.'.format(permission_id))
    except KeyError:
        print('No title for this item:')
        pprint.pprint(drive_item)

def grant_ownership(service, drive_item, prefix, permission_id, show_already_owned, batch):
    full_path = os.path.join(os.path.sep.join(prefix), drive_item['title']).encode('utf-8', 'replace')

    #pprint.pprint(drive_item)

    current_user_owns = False
    for owner in drive_item['owners']:
        if owner['permissionId'] == permission_id:
            if show_already_owned:
                print('Item {} already has the right owner.'.format(full_path))
            return
        elif owner['isAuthenticatedUser']:
            current_user_owns = True

    print('Item {} needs ownership granted.'.format(full_path))

    if not current_user_owns:
        print('    But, current user does not own the item.'.format(full_path))
        return

    print('    Creating new ownership permissions.')
    permission = {'role': 'writer',
                  'type': 'user',
                  'pendingOwner': True,
                  'id': permission_id}
    try:
        req = service.permissions().insert(fileId=drive_item['id'], body=permission, emailMessage='Automated recursive transfer of ownership.')
        batch.add(req)
    except googleapiclient.errors.HttpError as e:
        print('An error occurred inserting ownership permissions: {}'.format(e))

def list_files(service, folder_id = None, q = None, fields = ''):
    items = []
    page_token = None
    while True:
        param = {}
        if page_token:
            param['pageToken'] = page_token

        if folder_id:
            q = f"'{folder_id}' in parents"

        children = service.files().list(q=q, fields=f"items(id,{fields}),nextPageToken", **param).execute()
        items.extend(children.get('items', []))
        
        page_token = children.get('nextPageToken')
        if not page_token:
            break
    return items


def process_all_files(service, callback=None, callback_args=None, minimum_prefix=None, current_prefix=None, folder_id='root'):
    if minimum_prefix is None:
        minimum_prefix = []
    if current_prefix is None:
        current_prefix = []
    if callback_args is None:
        callback_args = []

    print('Gathering file listings for prefix {}...'.format(current_prefix))

    folder_items = list_files(service, folder_id=folder_id, fields='mimeType,kind,title,id,owners,shortcutDetails')

    try:
        for item in folder_items:
            if item['kind'] == 'drive#file':
                if item['mimeType'] == 'application/vnd.google-apps.shortcut':
                    item = service.files().get(fileId=item['shortcutDetails']['targetId'], fields='mimeType,title,id,owners').execute()

                if current_prefix[:len(minimum_prefix)] == minimum_prefix:
                    print(u'File: {} ({}, {})'.format(item['title'], current_prefix, item['id']))
                    callback(service, item, current_prefix, **callback_args)
                if item['mimeType'] == 'application/vnd.google-apps.folder':
                    print(u'Folder: {} ({}, {})'.format(item['title'], current_prefix, item['id']))
                    next_prefix = current_prefix + [item['title']]
                    comparison_length = min(len(next_prefix), len(minimum_prefix))
                    if minimum_prefix[:comparison_length] == next_prefix[:comparison_length]:
                        process_all_files(service, callback, callback_args, minimum_prefix, next_prefix, item['id'])
                        callback(service, item, current_prefix, **callback_args)
    except googleapiclient.errors.HttpError as e:
        print('An error occurred: {}'.format(e))

def receive_ownership(service, owner):
    children = list_files(service, q=f"'{owner}' in owners", fields='permissions')
    batch = Batch(service)
    pending_files = []
    for file in children:
        for perm in file.get('permissions', []):
            if perm.get('role') == 'writer' and perm.get('pendingOwner', False):
                pending_files.append(file)
                batch.add(service.permissions().update(fileId=file['id'], permissionId=perm['id'], transferOwnership=True, body={'role': 'owner'}))
    batch.execute()

def main():

    parser = argparse.ArgumentParser(description='Transfer ownership of all files in a Google Drive folder.')
    parser.add_argument('--auth', help='Choose between interactive or existing credentials file.', default='interactive')
    subparsers = parser.add_subparsers(dest='command')

    transfer_parser = subparsers.add_parser('transfer', help='Transfer ownership of all files in a Google Drive folder.')
    transfer_parser.add_argument('minimum_prefix', help='The minimum prefix of the path to transfer ownership of.')
    transfer_parser.add_argument('new_owner', help='The email address of the new owner.')
    transfer_parser.add_argument('--show-already-owned', help='Show files that are already owned by the new owner.', action='store_true')

    receive_parser = subparsers.add_parser('receive', help='receive ownership of all files in a Google Drive folder.')
    receive_parser.add_argument('owner', help='The current owner to receive from.')

    args = parser.parse_args()

    credentials = get_credentials(args.auth)
    http = httplib2.Http()
    credentials.authorize(http)
    oauth_service = googleapiclient.discovery.build('oauth2', 'v2', http=http)

    user_info = oauth_service.userinfo().get(fields='email').execute()

    with open(f"token_{user_info['email']}.json", "w") as token:
        token.write(credentials.to_json())

    drive_service = googleapiclient.discovery.build('drive', 'v2', http=http)

    if args.command == 'transfer':
        minimum_prefix = args.minimum_prefix
        new_owner = args.new_owner
        show_already_owned = args.show_already_owned
    
        print('Changing all files at path "{}" to owner "{}"'.format(minimum_prefix, new_owner))
        minimum_prefix_split = minimum_prefix.split(os.path.sep)
        print('Prefix: {}'.format(minimum_prefix_split))

        batch = Batch(drive_service)
        permission_id = get_permission_id_for_email(drive_service, new_owner)
        print('User {} is permission ID {}.'.format(new_owner, permission_id))
        process_all_files(drive_service, grant_ownership, {'permission_id': permission_id, 'show_already_owned': show_already_owned, 'batch': batch }, minimum_prefix_split)

        batch.execute()

    elif args.command == 'receive':
        receive_ownership(drive_service, args.owner)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
