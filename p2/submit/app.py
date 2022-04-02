"""
Copyright 2020 University of Maryland

All rights reserved.

Authors:
    - Michael Reininger
    - Joshua Fleming
    - Omer

This code may not be resdistributed without the permission of the copyright holders.
Any student solutions without prior approval is strictly prohibited.
This includes (but is not limited to) posting on public forums or web sites,
providing copies to (past, present, or future) students enrolled in similar Computer
and Network Security courses at the University of Maryland's CMSC414 course.
"""

from flask import Flask, redirect, render_template, render_template_string, session, url_for, request, abort, app, send_from_directory, make_response
from werkzeug.utils import secure_filename
import mysql.connector
import random
import re
import datetime
import os
import logging
import json

app = Flask(__name__)
app.secret_key = 'CMSC414'
app.config['SESSION_COOKIE_HTTPONLY'] = False
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
logging.basicConfig(level=logging.DEBUG, filename="test.log")

# Database configuration - not in scope of assignment
config = {
    'user': 'root',
    'password': 'CMSC414-r00t-Pa55word',
    'host': 'db',
    'port': '3306',
    'database': 'nowshare'
}

connection = mysql.connector.connect(**config)
def filter_level(value):
    whitelist = re.compile("[^0-9a-zA-Z \\?\\!\.\\(\\)]+", re.IGNORECASE)
    value = whitelist.sub("", value)
    return value

# Simple
def filter_level0(value):
    semi_colon = re.compile(";")   
    value = semi_colon.sub("", value)
    return value

# Hmm
def filter_level1(value):
    value = filter_level0(value)

    or_pattern = re.compile("or", re.IGNORECASE)
    and_pattern = re.compile("and", re.IGNORECASE)
    value = and_pattern.sub("", value)
    value = or_pattern.sub("",value)
    return value

# Uhh
def filter_level2(value):
    value = filter_level1(value)
    select_pattern = re.compile("select", re.IGNORECASE)
    insert_pattern = re.compile("insert", re.IGNORECASE)
    value = select_pattern.sub("",value)
    value = insert_pattern.sub("",value)
    return value

# Ugh
def filter_level3(value):
    value = filter_level2(value)
    where_pattern = re.compile("where", re.IGNORECASE)
    value = where_pattern.sub("",value)
    value = re.sub("\d+", "", value)
    return value

# Returns the currently logged in user
def current_user():
    if 'user' not in session.keys():
        return {}
    else:
        session_token = session['user']
        
        try:
            cursor = connection.cursor(prepared=True)
        except:
            return {}

        query = """SELECT username FROM sessions WHERE session_token = %s"""
        cursor.execute(query, (session_token,))

        u = [x for x in cursor]

        try:
            query1 = """SELECT * FROM users WHERE username= %s;"""
            cursor.execute(query1, (u[0][0],))
        except:
            return {}


        results = [{"username": username,
                    "full_name": full_name,
                    "description": description,
                    "profile_pic":profile_pic,
                    "followers": followers,
                    "following": following
                    } for (username, password, full_name, description, profile_pic, followers, following) in cursor]

        if len(results) > 0:
            
            query2 = "SELECT COUNT(followed_uname) FROM following_relations WHERE follower_uname= %s;"
            cursor.execute(query2, (results[0]['username'],))

            results[0]['following'] = [cnt[0] for cnt in cursor][0]

            query3 = "SELECT COUNT(follower_uname) FROM following_relations WHERE followed_uname= %s;"
            cursor.execute(query3, (results[0]['username'],))
            results[0]['followers'] = [cnt[0] for cnt in cursor][0]

            cursor.close()

            app.logger.info('current_user: ' + str(results[0]))

            return results[0]

        else:
            cursor.close()
            return {}

# Returns the user information for a particular user
def get_user(username):

    session_token = session['user']
    cursor = connection.cursor(prepared=True)

    query = """SELECT username FROM sessions WHERE session_token = %s"""
    cursor.execute(query, (session_token,))

    u = [x for x in cursor]

    try:
        query1 = """SELECT * FROM users WHERE username = %s"""
        cursor.execute(query1, (username,))
    except:
        return {}

    results = [{"username": username,
                "full_name": full_name,
                "description": description,
                "profile_pic": profile_pic,
                "followers": followers,
                "following": following
                } for (username, password, full_name, description, profile_pic, followers, following) in cursor]


    cursor.close()

    if len(results) > 0:
        return results[0]
    else:
        return None

# Checks if a filename is allowed when uploading
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Main event handler whenever a user visits the index or main page
@app.route('/')
@app.route('/index')
def index():

    # Check if session token exists
    if not 'user' in session.keys():
        return redirect(url_for('login'))

    # Get the current user
    user = current_user()

    # No user found, delete session token
    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    # Obtain all posts 
    cursor = connection.cursor(buffered=True)
    cursor.execute("SELECT * FROM posts WHERE share = 'yes';")
    

    start = datetime.datetime.now()

    # Collect all posts into list of dictionaries
    posts = []
    for post in cursor:
        app.logger.info(post)
        ts = str(post[1])
        f = '%Y-%m-%d %H:%M:%S'
        d = datetime.datetime.strptime(ts, f)
        delta = start - d
        time = ""
        if delta.total_seconds() / 60 > 60:
            time = str(int(delta.total_seconds() / 3600)) + " hours ago"
        else:
            time = str(int(delta.total_seconds() / 60)) + " minutes ago"

        posts.append({
            "username": "/"+post[0],
            "profile_pic":post[0]+'.png',
            "ts": post[1],
            "picture": post[2],
            "body": post[3],
            "likes": post[4],
            "comments": json.loads(post[5]),
            "share": post[6],
            "time": time,
            "post_id" : post[7]
        })

    posts.reverse()
    cursor.close()

    return render_template('index.html', user=user, posts=posts)

# Handler for posting images and content to the site
@app.route('/post', methods=['GET', 'POST'])
def post():

    if request.method != 'POST':
        app.logger.info('Not post')

        return redirect(url_for('index'))

    # No posting
    if not request.form.get("posting"):
        app.logger.info('No posting')

        return redirect(url_for('index'))

    # LOGGING
    app.logger.info("Files: "+ str(request.files))
    post_content = request.form.get("posting")
    app.logger.info("Post content: " + post_content)
    app.logger.info("Form: " + str(request.form))

    if 'files' not in request.files:
        app.logger.info('No file')
        return redirect(url_for('index'))

    file = request.files['files']

    if file.filename == '':
        redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(path)
        path = path.replace('static/', '')
        user = current_user()
        share = "yes"
        post_content = request.form.get("posting")

        private = request.form.get("private")
        if str(private) == 'on':
            share = "no"

        cursor = connection.cursor(buffered=True)
        query = """INSERT INTO posts (username, picture, body, likes, comments, share) VALUES \
        (%s," + "'" + path + "',%s," + str(0) + ",'{}',%s);"""
        cursor.execute(query, (user["username"], post_content, share,))

        cursor.close()

    return redirect(url_for('index'))


# Add comments
@app.route('/post/comment/<int:post_id>', methods=['GET', 'POST'])
def postcomment(post_id):

    if request.method != 'POST':
        app.logger.info('Not post')
        return redirect(url_for('index'))

    # No posting
    if not request.form.get("comment"):
        app.logger.info('No posting')
        return redirect(url_for('index'))
    
    comment_content = request.form.get("comment")
    
    # Security security security
    comment_content = filter_level3(comment_content)
    comment_content = filter_level(comment_content)
    
    user = current_user()
    app.logger.info("User " + str(user))

    # Get current comment string from database on a particular post
    query = "SELECT comments FROM posts WHERE post_id =" + str(post_id) + ";"
    
    try:
        cursor = connection.cursor(buffered=True)
    except:
        return redirect(url_for('index'))
    
    try:
        cursor.execute(query)
    except mysql.connector.errors.ProgrammingError:
        return redirect(url_for('index'))

    # Comment string from database
    comments = cursor.fetchone()[0]
    app.logger.info("Comments " +str(comments))
    
    separator = ""
    # If no comments, make separator a comma
    if comments != "{}":
        separator = ","
    
    updated_comments = comments[0:-1] + separator + "\"" + user["username"] + "\":\"" + comment_content + "\"}"
    app.logger.info("Updated " + str(updated_comments))
    
    try:
        # Update comments on post
        query = "UPDATE posts SET comments = %s WHERE post_id = " + str(post_id) + ";"
        app.logger.info(query)
        cursor.execute(query, (updated_comments,))
    
    except mysql.connector.errors.ProgrammingError:
        return redirect(url_for('index'))
    
    cursor.close()
    return redirect(url_for('index'))




# Returns the static route for the uploaded picture
@app.route('/uploads/<path:path>')
def send_pic(path):
    return send_from_directory('static/uploads', path)


# Handles searching the site
@app.route('/search', methods=['POST'])
def search():
    # Check if session token exists
    if 'user' not in session.keys():
        return redirect(url_for('login'))

    # Get the current user
    user = current_user()

    # Obtain search query from search bar
    search = request.form.get("search")

    # Sanitize input
    search = filter_level1(search)

    query = """SELECT * FROM posts WHERE (body LIKE %s OR username LIKE %s) AND share = 'yes';"""
    
    try:
        cursor = connection.cursor(buffered=True)
    except:
        return redirect(url_for('index'))

    
    try:
        cursor.execute(query, ("%" + search + "%", "%" + search + "%",))
    except mysql.connector.errors.ProgrammingError:
        return redirect(url_for('index'))


    start = datetime.datetime.now()

    # Collect all posts into list of dictionaries
    results = []
    for post in cursor:
        ts = str(post[1])
        f = '%Y-%m-%d %H:%M:%S'
        d = datetime.datetime.strptime(ts, f)
        delta = start - d
        time = ""
        if delta.total_seconds() / 60 > 60:
            time = str(int(delta.total_seconds() / 3600)) + " hours ago"
        else:
            time = str(int(delta.total_seconds() / 60)) + " minutes ago"

        results.append({
            "username": "/"+post[0],
            "profile_pic":post[0],
            "ts": post[1],
            "picture": post[2],
            "body": post[3],
            "likes": post[4],
            "comments": json.loads(post[5]),
            "share": post[6],
            "time": time,
            "post_id" : post[7]
        })


    results.reverse()
    cursor.close()
    
    # I think this is right? Good thing the Internet told me to do this!
    f = open('templates/results.html')
    temp = f.read()
    f.close()
    temp = temp.replace('FILL_SEARCH', search)

    return render_template_string(temp, user=user, results=results)

    # This line wasn't working earlier... Probably the safest way to do this.
    # return render_template('results.html', user=user, search=search, results=results)


# Handler for showing the user's profile settings
@app.route('/settings')
def settings():

    # Check if session token exists
    if not 'user' in session.keys():
        return redirect(url_for('login'))

    # Get the current user's information
    user = current_user()

    return render_template('settings.html', user=user, success=None)

# Handler for updating the user's profile settings
@app.route('/update_profile', methods=['POST'])
def update_profile():

    # Check if session token exists
    if 'user' not in session.keys():
        return redirect(url_for('login'))

    # Get full_name and description from settings field
    fn = request.form.get("full_name")
    desc = request.form.get("description")

    # Security security security
    fn = filter_level2(fn)
    desc = filter_level2(desc)

    user = current_user()
    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    cursor = connection.cursor(buffered=True)

    try:
        query = """UPDATE users SET full_name=%s, description= %s WHERE username = %s;"""
        cursor.execute(query, (fn, desc, user["username"],))

    except mysql.connector.errors.ProgrammingError:
        app.logger.info(query)
        return render_template('settings.html', user=user, success=False)

    cursor.close()

    # Get updated user data
    user = current_user()

    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    return render_template('settings.html', user=user, success=True)

@app.route('/update_password', methods=['POST'])
def update_password():

    # Check if session token exists
    if 'user' not in session.keys():
        return redirect(url_for('login'))
    
    # Get old password, new password, and new password (confirmed) from settings field
    old_pw = request.form.get("old_password")
    new_pw = request.form.get("new_password")
    confirm_pw =  request.form.get("confirm_password")

    # Security security security
    old_pw = filter_level2(old_pw)
    new_pw = filter_level2(new_pw)
    confirm_pw = filter_level2(confirm_pw)

    user = current_user()
    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    # New passwords must match
    if(new_pw != confirm_pw):
        app.logger.info("Passwords don't match")
        return render_template('settings.html', user=user, success=False)
    
    
    cursor = connection.cursor(buffered=True)

    query = """UPDATE users SET password = %s WHERE username = %s AND password = %s;"""

    try:
        app.logger.info(query)
        cursor.execute(query, (new_pw, user["username"], old_pw,))
        app.logger.info(cursor)
        
        # Update unsuccessful
        if cursor.rowcount == 0:
            return render_template('settings.html', user=user, success=False)

    except mysql.connector.errors.ProgrammingError:
        return render_template('settings.html', user=user, success=False)

    cursor.close()

    # Get updated user data
    user = current_user()

    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    return render_template('settings.html', user=user, success=True)



# Handler to authenticate a user at login
@app.route('/authenticate', methods=['POST', 'GET'])
def authenticate():

    # If user is already in session key, redirect to index
    if 'user' in session.keys():
        return redirect(url_for('index'))

    # Get username and password from login form
    username = request.form.get("username")
    password = request.form.get("password")


    cursor = connection.cursor(buffered=True)
    username = filter_level0(username)
    password = filter_level0(password)

    # Check if user exists in the `users` table
    try:
        query = """SELECT * FROM users WHERE username = %s and password = %s;"""
        cursor.execute(query, (username, password,))
    except:
        return redirect(url_for('login'))

    # Store query results
    results = [{"username": username,
                "full_name": full_name,
                "description": description,
                "profile_pic":profile_pic,
                "followers": followers,
                "following": following
                } for (username, password, full_name, description, profile_pic, followers, following) in cursor]
    cursor.close()

    if len(results) > 0:

        # Generate a random session token
        session_token = random.randint(0, 1000000)

        cursor = connection.cursor(buffered=True)

        # Insert session token into sessions database
        query = """INSERT INTO sessions (session_token, username) VALUES (%s, %s);"""
        cursor.execute(query, (session_token, username,))

        cursor.close()

        # Set the session token for the user
        session['user'] = session_token
        return redirect(url_for('index'))

    else:
        return redirect(url_for('login'))


# Handler to route user to login page
@app.route('/login')
def login():
    # If the user is already logged in, then
    # redirect to index
    if 'user' in session.keys():
        return redirect(url_for('index'))

    return render_template('auth/login.html')


# Handler to logout a user
@app.route('/logout')
def logout():

    # If the user is not logged in, then
    # redirect user to the login
    if 'user' not in session.keys():
        return redirect(url_for('login'))

    user = current_user()

    # Clear the session token for the current user
    if user != {}:
        cursor = connection.cursor(buffered=True)
        query = """DELETE FROM sessions WHERE username = %s;"""
        cursor.execute(query, (user['username'],))
        cursor.close()

    # Remove the session token from the user
    del session['user']

    return redirect(url_for('login'))

# Handler to follow a user
@app.route('/modify_relation/<follow>')
def modify_relation(follow):

    # If the user is not logged in, then
    # redirect user to the login
    if 'user' not in session.keys():
        return redirect(url_for('login'))

    user = current_user()
    cursor = connection.cursor(buffered=True)
    query = "SELECT followed_uname FROM following_relations WHERE follower_uname= %s;"
    cursor.execute(query, (user['username'],))
    followed_by_user_results = [username[0] for username in cursor]

    if follow in followed_by_user_results:
        # Execute unfollow query
        follow = filter_level(follow)
        queryd = "DELETE FROM following_relations WHERE followed_uname= %s AND follower_uname= %s;"
        cursor.execute(queryd, (follow, user['username'],))
                       
    else:
        # Execute follow
        follow = filter_level(follow)
        queryi = "INSERT INTO following_relations (followed_uname, follower_uname) VALUES (%s, %s);"
        cursor.execute(queryi, (follow, user['username'],))


    cursor.close()

    return redirect(url_for('user_page', username=follow))


# Handler to visit a user's page
@app.route('/u/<username>')
def user_page(username):
    app.logger.info("App route for: " + username)
    # Check if session token exists
    if 'user' not in session.keys():
        app.logger.info("User not in session keys: user page")
        return redirect(url_for('login'))

    # Get the current user
    user = current_user()

    # No user found, delete session token
    if user == {}:
        app.logger.info("No user found: user page")
        del session['user']
        return redirect(url_for('index'))

    no_follow = False
    #app.logger.info(str(user) + " " + username)
    if user['username'] == username:
        no_follow = True

    # Security security security
    username = filter_level3(username)

    user_data = get_user(username)

    if user_data == None:
        app.logger.info("No user data for " + username)
        return redirect(url_for('index'))
    else:
        # Obtain all posts
        cursor = connection.cursor(buffered=True)
        query = "SELECT * FROM posts WHERE username = %s and share = 'yes';"
        cursor.execute(query, (username,))

        start = datetime.datetime.now()

        # Collect all posts into list of dictionaries
        posts = []
        for post in cursor:
            ts = str(post[1])
            f = '%Y-%m-%d %H:%M:%S'
            d = datetime.datetime.strptime(ts, f)
            delta = start - d
            time = ""
            if delta.total_seconds() / 60 > 60:
                time = str(int(delta.total_seconds() / 3600)) + " hours ago"
            else:
                time = str(int(delta.total_seconds() / 60)) + " minutes ago"

            posts.append({
                "username": "/"+post[0],
                "profile_pic":post[0],
                "ts": post[1],
                "picture": "/"+post[2],
                "body": post[3],
                "likes": post[4],
                "comments": post[5],
                "share": post[6],
                "time": time,
                "post_id": post[7]
            })

        posts.reverse()
        query = "SELECT follower_uname FROM following_relations WHERE followed_uname= %s;"
        cursor.execute(query, (username,))
        followers_results = [username[0] for username in cursor]

        query1 = "SELECT followed_uname FROM following_relations WHERE follower_uname= %s;"
        cursor.execute(query1, (user['username'],))
        curr_user_following_results = [username[0] for username in cursor]
        
        query2 = "SELECT followed_uname FROM following_relations WHERE follower_uname= %s;"
        cursor.execute(query2, (username,))
        curr_page_following_results = [username[0] for username in cursor]


        if username in curr_user_following_results:
            follow = False
        else:
            follow = True



        cursor.close()

        return render_template('user.html', user=user_data, results=posts,
                                followers_results=followers_results, following_results=curr_page_following_results,  no_follow=no_follow, follow=follow)

# Handler to route users to about page
@app.route('/about')
def about():
    return render_template('about.html')


# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
