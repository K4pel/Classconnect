from app import app, get_db

def check_admins():
    """Check existing admin users"""
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT id, username FROM users WHERE is_admin = 1')
        admins = cur.fetchall()
        print('Existing admins:')
        for admin in admins:
            print(f'  - ID: {admin[0]}, Username: {admin[1]}')
        return admins

def delete_all_admins():
    """Delete all existing admin users"""
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT id, username FROM users WHERE is_admin = 1')
        admins = cur.fetchall()
        
        if not admins:
            print('No admins found to delete.')
            return
            
        print('Deleting admins:')
        for admin in admins:
            print(f'  - ID: {admin[0]}, Username: {admin[1]}')
            cur.execute('DELETE FROM users WHERE id = ?', (admin[0],))
        
        db.commit()
        print(f'Deleted {len(admins)} admin(s).')

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "delete":
        delete_all_admins()
    else:
        check_admins()