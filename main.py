from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from html_sanitizer import Sanitizer
import os
from dotenv import load_dotenv
import smtplib

load_dotenv()

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")
TARGET_EMAIL = os.getenv("TARGET_EMAIL")
PORT = os.getenv("PORT")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASS = os.getenv("ADMIN_PASS")

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if (current_user.is_authenticated and current_user.role != "admin") or not current_user.is_authenticated:
            return abort(403)
        return f(*args, **kwargs)        
    return decorated_function

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
ckeditor = CKEditor(app)
Bootstrap5(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE")
db = SQLAlchemy()
db.init_app(app)

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    #Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    role = db.Column(db.String(10), nullable=False, default='user')
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
    
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost",back_populates="comments")

@app.before_request
def setup():
    with app.app_context():
        db.create_all()
        create_admin()
        
def create_admin():
    admin = User.query.filter_by(email=ADMIN_EMAIL).first()
    if not admin:
        hash_and_salted_password = generate_password_hash(
            ADMIN_PASS,
            method='pbkdf2:sha256',
            salt_length=8
        )
        admin = User(
            email=ADMIN_EMAIL, 
            password=hash_and_salted_password, 
            role='admin',
            name='Admin'
        )
        db.session.add(admin)
        db.session.commit()

@app.route('/register', methods=["GET", "POST"])
def register():
    logged_in = current_user.is_authenticated
    
    if logged_in:
        return redirect(url_for("get_all_posts"))
    
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        result = db.session.execute(db.select(User).where(User.email==email))
        user = result.scalar()
        
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        
        new_user = User(
            email = form.email.data,
            name = form.name.data,
            password = hash_and_salted_password
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form = form, logged_in = current_user.is_authenticated)
 
@app.route('/login', methods=["GET", "POST"])
def login():
    logged_in = current_user.is_authenticated
    
    if logged_in:
        return redirect(url_for("get_all_posts"))
    
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("get_all_posts"))
        else:
            flash('Email or Password incorrect, please try again.')
            return redirect(url_for('login'))
        
    return render_template("login.html", form=form, logged_in = current_user.is_authenticated)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/')
def get_all_posts():
    role = None
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    logged_in = current_user.is_authenticated
    
    if logged_in:
        role = current_user.role
        
    admin_role = True if role == "admin" else False
    return render_template("index.html", all_posts=posts, logged_in = logged_in, admin_role = admin_role)

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    sanitizer = Sanitizer()
    form = CommentForm()
    role = None
    requested_post = db.get_or_404(BlogPost, post_id)
    logged_in = current_user.is_authenticated
    
    if logged_in:
        role = current_user.role
        
    admin_role = True if role == "admin" else False
        
    if form.validate_on_submit():
        if not logged_in:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        
        new_comment = Comment(
            text = sanitizer.sanitize(form.comment.data),
            comment_author = current_user,
            parent_post = requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=requested_post.id))
    return render_template("post.html", post=requested_post, logged_in = logged_in, admin_role = admin_role, form=form, gravatar = gravatar)

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in = current_user.is_authenticated)

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in = current_user.is_authenticated)

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/about")
def about():
    logged_in = current_user.is_authenticated
    return render_template("about.html", logged_in = logged_in)

@app.route("/contact", methods=["GET", "POST"])
def contact():
    logged_in = current_user.is_authenticated
    if request.method == 'POST':
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        message = request.form["message"]
        
        with smtplib.SMTP("smtp.gmail.com", port=PORT) as connection:
            connection.starttls()
            connection.login(user=EMAIL, password=PASSWORD)
            connection.sendmail(
                from_addr=EMAIL, 
                to_addrs=TARGET_EMAIL, 
                msg=f"Subject:New Message\n\nName : {name}\nEmal : {email}\nPhone Number : {phone}\nMessage : {message}")
        return render_template("contact.html", msg_sent = True, logged_in = logged_in)
    else:
        return render_template("contact.html", msg_sent = False, logged_in = logged_in)

if __name__ == "__main__":
    app.run(debug=True)
