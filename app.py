from flask import Flask, render_template, redirect, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
import pytz
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = os.urandom(24)

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
  __tablename__ = "users"
  id = db.Column(db.Integer, primary_key=True, unique=True)
  name = db.Column(db.String(30), nullable=False, unique=True)
  password = db.Column(db.String(255), nullable=False)

class Task(db.Model):
  __tablename__ = "tasks"
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(50), nullable=False)
  detail = db.Column(db.String(100), nullable=True)
  limit = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.timezone('Asia/Tokyo')))
  is_finished = db.Column(db.Integer, nullable=False, default=0)
  sent_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
  received_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Group(db.Model):
  __tablename__ = "groups"
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(50), nullable=False, unique=True)
  hashed_join_password = db.Column(db.String(256), nullable=False)

class Group_member(db.Model):
  __tablename__ = "group_members"
  id = db.Column(db.Integer, primary_key=True)
  group_id = db.Column(db.Integer, db.ForeignKey("groups.id"), nullable=False)
  user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_first_request
def init():
    db.create_all()


@app.route("/", methods=["GET", "POST"])
def index():
  if request.method == "GET":
    if "user_id" in session:
      tasks = Task.query.filter_by(received_user_id=session["user_id"]).filter_by(is_finished=0)
      sent_users = []
      for task in tasks:
        sent_user= User.query.filter_by(id=task.sent_user_id).one()
        sent_users.append(sent_user)
      return render_template("index.html", tasks=tasks, sent_users=sent_users)
    else:
      return redirect("/login")
  else:
    return render_template("index.html")
  
@app.route("/progress",methods=["GET"])
@login_required
def progress():
  if request.method == "GET":
    if "user_id" in session:
      not_finished_tasks = Task.query.filter_by(sent_user_id=session["user_id"]).filter_by(is_finished=0)
      not_finished_users = []
      for not_finished_task in not_finished_tasks:
        not_finished_user = User.query.filter_by(id=not_finished_task.received_user_id).one()
        not_finished_users.append(not_finished_user)
      
      finished_tasks = Task.query.filter_by(sent_user_id=session["user_id"]).filter_by(is_finished=1) 
      finished_users = []
      for finished_task in finished_tasks:
        finished_user = User.query.filter_by(id=finished_task.received_user_id).one()
        finished_users.append(finished_user)      
      
           
      return render_template("progress.html", not_finished_tasks=not_finished_tasks, not_finished_users=not_finished_users,finished_tasks=finished_tasks, finished_users=finished_users, )
    else:
      return redirect("/login")
  
@app.route("/task_delete/<id>")
def task_delete(id):
  task = Task.query.filter_by(id=id).one()
  task.is_finished = 1
  db.session.add(task)
  db.session.commit()
  flash("タスクから削除しました")
  return redirect("/")
  
@app.route("/group", methods=["GET", "POST"])
@login_required
def group():
  if request.method == "GET":
    return render_template("group.html")
  
@app.route("/make_group", methods=["GET", "POST"])
@login_required
def make():
  if request.method == "POST":
    groupname = request.form.get("groupname")
    password = request.form.get("password")
    if not groupname:
      flash("グループ名を入力してください")
      return redirect("/make_group")
    elif not password:
      flash("パスワードを入力してください")
      return redirect("/make_group")
    if Group.query.filter_by(name=groupname).first() is None:
      newgroup = Group(name = groupname, hashed_join_password = generate_password_hash(password, method='sha256'))
      db.session.add(newgroup)
      db.session.commit()
      group_id = newgroup.id
      group_maker_id = session["user_id"]
      first_member = Group_member(user_id = group_maker_id, group_id = group_id)
      db.session.add(first_member)
      db.session.commit()    
      flash("作成しました")
      return redirect("/")
    else:
      flash("このグループ名は既に使われています")
      return redirect("/make_group")
  else:
    return render_template("make_group.html")


@app.route("/join", methods=["GET", "POST"])
@login_required
def join():
  if request.method == "POST":
    groupname = request.form.get("groupname")
    password = request.form.get("password")
    if not groupname:
      flash("グループ名を入力してください")
      return redirect("/join")
    elif not password:
      flash("パスワードを入力してください")
      return redirect("/join")
    group = Group.query.filter_by(name=groupname).first()   
    if check_password_hash(group.hashed_join_password, password):
      group_id = group.id
      user_id = session["user_id"]
      if Group_member.query.filter_by(group_id=group_id).filter_by(user_id=user_id).first():
        flash("すでに参加しています")
        return redirect("/join")
      else:
        member= Group_member(user_id = user_id, group_id = group_id)
        db.session.add(member)
        db.session.commit()
        flash("グループに参加しました")
        return redirect('/')
    else:
      flash("パスワードが一致していません")
      return redirect("/join")
  else:
    return render_template("join.html")

@app.route("/leave", methods=["GET", "POST"])
@login_required
def leave():
  if request.method == "POST":
    return redirect("/")
  else:
    rows = Group_member.query.filter_by(user_id=session["user_id"])
    groups = []
    for row in rows:
      group = Group.query.filter_by(id=row.group_id).one()
      groups.append(group)
    return render_template("leave.html", groups=groups)
  
@app.route("/withdraw/<int:id>")
@login_required
def withdraw(id):
  row = Group_member.query.filter_by(user_id=session["user_id"]).filter_by(group_id=id).one()
  db.session.delete(row)
  db.session.commit()
  flash("退会しました")
  return redirect("/leave")

@app.route("/select_group", methods=["GET", "POST"])
@login_required
def select_group():
  if request.method == "POST":
    return redirect("/")
  else:
    rows = Group_member.query.filter_by(user_id=session["user_id"])
    groups = []
    for row in rows:
      group = Group.query.filter_by(id=row.group_id).one()
      groups.append(group)
    return render_template("select_group.html", groups=groups)

@app.route('/select_member/<id>')
def select_member(id):
  rows = Group_member.query.filter_by(group_id=id)
  members = []
  for row in rows:
    member = User.query.filter_by(id=row.user_id).one()
    members.append(member)
  return render_template("select_member.html", members=members)

@app.route('/make_task/<id>', methods=["GET", "POST"])
def make_task(id):
  if request.method == "POST":
    task_name = request.form.get("taskname")
    task_detail = request.form.get("detail")
    limit_date= datetime.strptime(request.form.get("limit_date") + " " + request.form.get("limit_time"), '%Y-%m-%d %H:%M')
    task = Task(name=task_name, detail=task_detail, limit=limit_date, is_finished=0, sent_user_id=session["user_id"], received_user_id=id)
    db.session.add(task)
    db.session.commit()
    flash("タスクを送信しました")
    return redirect("/")
  else:
    return render_template("/make_task.html",id=id)

@app.route("/login", methods=["GET", "POST"])
def login():
  session.clear()
  if request.method == "POST":
    session.permanent = True
    username = request.form.get('username')
    password = request.form.get('password')
    if not username:
      flash("ユーザーネームを入力してください")
      return redirect("/login")
    elif not password:
      flash("パスワードを入力してください")
      return redirect("/login")
    user = User.query.filter_by(name=username).first()
    if check_password_hash(user.password, password):
      session["user_id"] = user.id
      login_user(user)
      flash("ログインできました")
      return redirect('/')
    else:
      flash("パスワードが違います")
      return redirect("/login")
  else:
    return render_template("login.html")

@app.route("/logout",methods=['GET'])
@login_required
def logout():
  session.clear()
  logout_user()
  flash("ログアウトしました")
  return redirect("/login")

@app.route("/signup", methods=['GET','POST'])
def signup():
  if request.method == "POST":
    username = request.form.get('username')
    password = request.form.get('password')
    if not username:
      flash("ユーザーネームを入力してください")
      return redirect("/signup")
    elif not password:
      flash("パスワードを入力してください")
      return redirect("/signup")
    if User.query.filter_by(name=username).first() is None:    
      user = User(name = username, password = generate_password_hash(password, method='sha256'))
      db.session.add(user)
      db.session.commit()
      return redirect('login')
    else:
      flash("このユーザーネームはすでに使われています")
      return redirect("/signup")
  else:
    return render_template("signup.html")

if __name__ == '__main__':
	app.run(debug=True)