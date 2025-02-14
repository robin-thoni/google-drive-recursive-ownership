# Google Drive Recursive Ownership Tool

### Supported Files

G Suite for Government and G Suite for Education accounts can change ownership of any file owned by the current user, including uploaded/synced files suchs as PDFs.

Other Google Accounts such as G Suite for Business or Personal Google Accounts can only transfer ownership of Google files (Docs, Sheets, Sildes, Forms, Drawings, My Maps, and folders).

NOTE: Ownership can only be transferred to members of the same G Suite or Google domain. Ex. @gmail.com can only transfer to other @gmail.com addresses.

NOTE: The Google Drive API does not allow suppressing notifications for change of ownership if the _if_ the new owner does not already have access to the file. However, if the new owner _already_ has access to the file, upgrading their permissions to ownership will _not_ generate a notification.

### Setup

    git clone https://github.com/robin-thoni/google-drive-recursive-ownership
    pip install -r requirements.txt

### Usage

First, replace the [sample](https://github.com/gsuitedevs/python-samples/blob/d4fa75401e9b637f67da6fe021801d8b4cbd8cd0/drive/driveapp/client_secrets.json) `client_secrets.json` with your own [client secrets](https://github.com/googleapis/google-api-python-client/blob/master/docs/client-secrets.md). Otherwise, authorizations you create will be usable by anyone with access to the sample key (the entire internet).


Start transfer:

```
# Windows Example:
python transfer.py transfer "Folder 1\Folder 2\Folder 3" new_owner@example.com --show-already-owned

# Mac/Linux Example:
python transfer.py transfer "Folder 1/Folder 2/Folder 3" new_owner@example.com
```

Receive files

```
python transfer.py receive previous_owner@example.com
```

### Refs

- https://developers.google.com/identity/protocols/oauth2/resources/oob-migration#desktop-client
- https://developers.google.com/drive/api/guides/performance#overview
- https://developers.google.com/drive/api/guides/shortcuts
- https://developers.google.com/drive/api/guides/fields-parameter
- https://developers.google.com/drive/api/reference/rest/v2/files/get
- https://developers.google.com/drive/api/reference/rest/v2/files/list
- https://developers.google.com/drive/api/reference/rest/v2/permissions/update
- https://developers.google.com/drive/api/guides/search-files#python
- https://developers.google.com/drive/api/guides/v2-to-v3-reference
