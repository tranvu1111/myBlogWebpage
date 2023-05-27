import functools
import os
import flask
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

import forms
from forms import CreatePostForm , RegisterForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ["MY_BLOG_SECRET_KEY"]
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

## LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

def admin_only(f):
    @functools.wraps(f)
    def decorated_funtion(*args,**kwargs):
        if current_user.id == 1 :
            return f(*args, *kwargs)
        return abort(403)
    return decorated_funtion



##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment",back_populates="parent_post")

class User(UserMixin,db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False , unique=True)
    name = db.Column(db.String(250), nullable=False)
    hash = db.Column(db.String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer,primary_key = True)
    text = db.Column(db.String(), nullable= False)

    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates = "comments")


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,current_user=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    error = None
    form = RegisterForm()

    if form.validate_on_submit():
        email = form.email.data
        user_check = bool(User.query.filter_by(email=email).first())
        if user_check:
            flash( "You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        hash = generate_password_hash(form.password.data,salt_length=8)
        new_user = User(
            email = email,
            name = form.name.data,
            hash = hash,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, error=error,current_user=current_user)


@app.route('/login', methods = ["POST", "GET"])
def login():
    error = None
    form = forms.LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            error = "Invalid email!"
        elif not check_password_hash(pwhash=user.hash , password=password):
            error = "Invalid password!"
        else:
            flash("You were successfully logged in")
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template("login.html",form=form, error=error,current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    comment_form = forms.Comment()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login to add comment.")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(
                text = comment_form.comment.data,
                author = current_user,
                parent_post = requested_post
            )
            db.session.add(new_comment)
            db.session.commit()

    return render_template("post.html", post=requested_post ,comment_form=comment_form , comments=requested_post.comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods= ["POST", "GET"])
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
    return render_template("make-post.html", form=form ,current_user=current_user)


@app.route("/edit-post/<int:post_id>",methods= ["POST", "GET"])
@admin_only

def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>",methods= ["POST", "GET"])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
