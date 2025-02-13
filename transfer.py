#!/usr/bin/python

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


def get_drive_service():
    OAUTH2_SCOPE = 'https://www.googleapis.com/auth/drive'

    if os.path.exists("token.json"):
        with open("token.json", "r") as token:
            credentials = oauth2client.client.OAuth2Credentials.from_json(token.read())
    else:
        CLIENT_SECRETS = 'client_secrets.json'
        flow = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS, OAUTH2_SCOPE)
        flow.redirect_uri = "http://localhost:8080"
        authorize_url = flow.step1_get_authorize_url()
        print('Use this link for authorization: {}'.format(authorize_url))
        code = start_server()
        credentials = flow.step2_exchange(code)
        with open("token.json", "w") as token:
            token.write(credentials.to_json())
    http = httplib2.Http()
    credentials.authorize(http)
    drive_service = googleapiclient.discovery.build('drive', 'v2', http=http)
    return drive_service

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

def process_all_files(service, callback=None, callback_args=None, minimum_prefix=None, current_prefix=None, folder_id='root'):
    if minimum_prefix is None:
        minimum_prefix = []
    if current_prefix is None:
        current_prefix = []
    if callback_args is None:
        callback_args = []

    print('Gathering file listings for prefix {}...'.format(current_prefix))

    page_token = None
    while True:
        try:
            param = {}
            if page_token:
                param['pageToken'] = page_token
            children = service.children().list(folderId=folder_id, fields='items/id,nextPageToken', **param).execute()
            for child in children.get('items', []):
                item = service.files().get(fileId=child['id'], fields='mimeType,kind,title,id,owners,shortcutDetails').execute()
                #pprint.pprint(item)
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
            page_token = children.get('nextPageToken')
            if not page_token:
                break
        except googleapiclient.errors.HttpError as e:
            print('An error occurred: {}'.format(e))
            break


class Batch:
    def __init__(self, service):
        self.service = service
        self.batch = service.new_batch_http_request()

    def add(self, request):
        self.batch.add(request)
        if len(self.batch._order) >= 100:
            self.execute()

    def execute(self):
        if self.batch._order:
            self.batch.execute()


def main():
    minimum_prefix = six.text_type(sys.argv[1])
    new_owner = six.text_type(sys.argv[2])
    show_already_owned = False if len(sys.argv) > 3 and six.text_type(sys.argv[3]) == 'false' else True
    print('Changing all files at path "{}" to owner "{}"'.format(minimum_prefix, new_owner))
    minimum_prefix_split = minimum_prefix.split(os.path.sep)
    print('Prefix: {}'.format(minimum_prefix_split))
    service = get_drive_service()

    batch = Batch(service)
    permission_id = get_permission_id_for_email(service, new_owner)
    print('User {} is permission ID {}.'.format(new_owner, permission_id))
    process_all_files(service, grant_ownership, {'permission_id': permission_id, 'show_already_owned': show_already_owned, 'batch': batch }, minimum_prefix_split)

    batch.execute()

    #print(files)


if __name__ == '__main__':
    main()
