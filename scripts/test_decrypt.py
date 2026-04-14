from iphone_backup_decrypt import EncryptedBackup
import time, os

bp = r'C:\Users\JUSTI\AppData\Roaming\Apple Computer\MobileSync\Backup\00008120-000214DC14EB401E\00008120-000214DC14EB401E'
print('Opening backup...')
t0 = time.time()
b = EncryptedBackup(backup_directory=bp, passphrase='scout1234')
print(f'Opened in {time.time()-t0:.1f}s')

t1 = time.time()
try:
    b.extract_file(relative_path='Library/Safari/History.db', domain_like='HomeDomain', output_filename='test_safari.db')
    print(f'Safari extracted in {time.time()-t1:.1f}s')
except Exception as e:
    print(f'Safari failed: {e}')

t2 = time.time()
try:
    b.extract_file(relative_path='Library/SMS/sms.db', domain_like='HomeDomain', output_filename='test_sms.db')
    print(f'SMS extracted in {time.time()-t2:.1f}s')
except Exception as e:
    print(f'SMS failed: {e}')

for f in ['test_safari.db', 'test_sms.db']:
    if os.path.exists(f):
        print(f'{f}: {os.path.getsize(f)} bytes')
        os.remove(f)
