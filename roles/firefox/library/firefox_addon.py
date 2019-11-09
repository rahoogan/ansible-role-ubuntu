#!/usr/bin/python

# TODO: agregar soporte para extensiones externas (url a archivo xpi)
# TODO: instalar temas

from ansible.module_utils.basic import *
from tempfile import mkdtemp
from urlparse import urlsplit
from zipfile import ZipFile
from collections import OrderedDict
import ConfigParser
import shutil
import os
import requests
import hashlib

class FirefoxExtension:
    def __init__(self, slug, profile_path, verify):
        self.slug = slug
        self.profile_path = profile_path
        self.verify = verify
        self._get_info()
        self.download_path = os.path.join(mkdtemp(), self.filename)
        self.destination = os.path.join(profile_path, 'extensions', '%s.xpi' % self.guid)

    def _get_info(self):
        url = 'https://addons.mozilla.org/api/v4/addons/addon/' + self.slug
        r = requests.get(url)
        if r.status_code != 200:
            raise Exception('Could not download info for %s from %s' % (self.slug, url))
        info = r.json()
        self.info = info['current_version']
        self.id = self.info['files'][0]['id']
        self.guid = info['guid']
        self.filename = '{slug}-{version}.xpi'.format(slug=info['slug'], version=self.info['version'])

    def _download(self):
        url = self.info['files'][0].get('url')
        if not url:
            raise Exception('No download url found for add on: %s' % self.slug)
        r = requests.get(url, stream=True)
        if self.verify:
            file_hash = self.info['files'][0].get('hash')
            if not file_hash:
                raise Exception('Could not verify extension %s, no verification hash found' % self.slug)
            else:
                hash_type, hashstr = file_hash.split(':')
 
            if hasattr(hashlib, hash_type) and callable(getattr(hashlib, hash_type)):
                computed_hash = getattr(hashlib, hash_type)()
            else:
                raise Exception('Unsupported hash type (%s) found when verifying add on: %s' % (hash_type, self.slug))

        if r.status_code == 200:
            with open(self.download_path, 'wb') as f:
                for chunk in r:
                    f.write(chunk)
                    if self.verify:
                        computed_hash.update(chunk)

        if self.verify:
            computed_hash = computed_hash.hexdigest()
            if computed_hash != hashstr:
                raise Exception('Verification failed for add on: %s (Expected: %s, Found: %s)' % (self.slug, hashstr, computed_hash))

    def is_installed(self):
        return os.path.isfile(self.destination)

    def install(self):
        path = os.path.dirname(self.destination)
        try:
            os.makedirs(path, 0700)
        except OSError:
            if not os.path.isdir(path):
                raise
        self._download()
        shutil.move(self.download_path, self.destination)

    def uninstall(self):
        os.remove(self.destination)


class FirefoxProfiles:
    """Class to manage firefox profiles."""

    def __init__(self, path):
        self.path = os.path.expanduser(path)
        self.profiles_ini = os.path.join(self.path, 'profiles.ini')
        self.config = ConfigParser.RawConfigParser()
        # Make options case sensitive
        self.config.optionxform = str
        self.read()

    def read(self):
        self.config.read(self.profiles_ini)
        self.sections = OrderedDict()
        for section in self.config.sections():
            if section.startswith('Profile'):
                profile = dict(self.config.items(section))
                self.sections[profile['Name']] = section

    def get(self, name):
        if name in self.sections:
            return dict(self.config.items(self.sections[name]))

    def get_path(self, name):
        profile = self.get(name)
        if (bool(profile['IsRelative'])):
            return os.path.join(self.path, profile['Path'])
        return profile['Path']


def main():
    fields = {
        'name': {'required': True, 'type': 'str'},
        'profile': {'default': 'default', 'type': 'str'},
        'path': {'default': '~/.mozilla/firefox', 'type': 'str'},
        'state': {
            'default': 'present',
            'choices': ['present', 'absent'],
            'type': 'str',
        },
        'verify': {'default': True, 'type': 'bool'},
    }
    module = AnsibleModule(argument_spec=fields)
    profiles = FirefoxProfiles(module.params['path'])
    profile = profiles.get(module.params['profile'])

    if profile is None:
        module.fail_json(msg='Profile %s not found' % module.params['profile'])

    path = profiles.get_path(module.params['profile'])
    addon = FirefoxExtension(module.params['name'], path, module.params['verify'])
    changed = False
    result = None

    try:
        if module.params['state'] == 'present' and not addon.is_installed():
            addon.install()
            changed = True
            result = {'id': addon.id, 'url': addon.url(), 'name': addon.filename}
        elif module.params['state'] == 'absent' and addon.is_installed():
            addon.uninstall()
            changed = True
        module.exit_json(changed=changed, meta=result)
    except Exception as e:
        module.fail_json(msg=e.message)


if __name__ == '__main__':
    main()
