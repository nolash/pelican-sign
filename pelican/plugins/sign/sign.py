# standard imports
import logging
import hashlib
import os
import shutil

# external imports
import gnupg

# local imports
from pelican import signals

logg = logging.getLogger(__name__)

gpg = None
gpg_keyid = None

def sum_and_sign(path, context):
    for k in context.keys():
        logg.debug('context {} {}'.format(k, context[k]))

    if 'article' not in context.keys():
        return

    f = open(os.path.realpath(path), 'rb')
    b = b''
    while True:
        r = f.read()
        if len(r) == 0:
            break
        b += r
    f.close()

    h = hashlib.new('sha256')
    h.update(b)
    z = h.digest().hex()

    output_sign_path = os.path.dirname(path)
    try:
        os.mkdir(output_sign_path)
    except FileExistsError:
        pass

    logg.debug('using signature dir {} from {}'.format(output_sign_path, os.path.dirname(path)))
    os.makedirs(output_sign_path, exist_ok=True)
    file_name = os.path.basename(path)
    (stem, ext) = os.path.splitext(file_name)
    sig_path = os.path.join(output_sign_path, z + '.asc')
    gpg.sign(b,  detach=True, keyid=gpg_keyid, output=sig_path, extra_args=['--digest-algo', 'sha256'])

    reverse_path = os.path.join(output_sign_path, z)
    shutil.copy(path, reverse_path)
    
    sum_path = os.path.join(output_sign_path, stem + '.sha256')
    f = open(sum_path, 'w')
    c = 0
    while True:
        r = f.write(z[c:])
        if r == 0:
            break
        c += r
    f.write("\x09" + file_name)
    f.close()



def set_sign_path(o):
    global output_sign_path
    global gpg
    global gpg_keyid 

    for k in o.settings.keys():
        logg.debug('setting {} {}'.format(k, o.settings[k]))


    logg.debug('opath {}'.format(o.path))
    gpg_dir = os.path.join(o.path, '.gnupg')

    try:
        os.mkdir(gpg_dir)
    except FileExistsError:
        pass

    gpg = gnupg.GPG(use_agent=True)

    gpg_keyid = o.settings.get('PLUGIN_SIGN_GPGKEY')
    logg.info('using gpg key {}'.format(gpg_keyid))


def register():
    signals.content_written.connect(sum_and_sign)
    signals.initialized.connect(set_sign_path)
