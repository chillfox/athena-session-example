require "athena"
require "ecr"
require "openssl/hmac"
require "crypto/bcrypt/password"

# require "base64"

############
# Settings #
############

# Pretend database
class Database
  @@users = [
    User.new("user1", "pass", true),
    User.new("user2", "pass"),
  ]

  @@sessions = [] of Session

  def self.users
    @@users
  end

  def self.sessions
    @@sessions
  end

  def self.sessions=(@@sessions)
  end
end

SESSION_SECRET = Random::Secure.random_bytes(8).hexstring

# SESSION_SECRET = "secret"

###########
# Helpers #
###########

macro render_view(filename)
  ECR.render "src/views/#{{{filename}}}.ecr"
end

##########
# Models #
##########

class User
  getter username : String
  getter password_hash : String
  getter admin : Bool

  def initialize(@username, password, @admin = false)
    @password_hash = Crypto::Bcrypt::Password.create(password).to_s
  end

  def verify_password(password)
    pw = Crypto::Bcrypt::Password.new @password_hash
    pw.verify password
  end

  def self.find?(username)
    Database.users.select { |u| u.username == username }.try &.first
  end
end

class Session
  getter id : String
  getter token : String
  getter username : String

  def initialize(@username)
    @id = Random::Secure.random_bytes(8).hexstring
    signature = OpenSSL::HMAC.hexdigest(:sha1, SESSION_SECRET, @id)
    @token = "#{@id}--#{signature}"
  end

  def save
    Database.sessions << self
  end

  def delete
    Database.sessions.reject! { |s| s.id == id }
  end

  def self.valid?(token)
    return false unless token.split("--").size == 2
    id, signature = token.split("--")
    new_signature = OpenSSL::HMAC.hexdigest(:sha1, SESSION_SECRET, id)
    new_signature == signature
  end

  def self.find?(token)
    id = token.split("--").first
    Database.sessions.select { |s| s.id == id }.try &.first
  end
end

@[ADI::Register]
class SessionStorage
  property user : User?
  property session : Session?
end

#############
# listeners #
#############

@[ADI::Register]
struct SessionListener
  include AED::EventListenerInterface

  def self.subscribed_events : AED::SubscribedEvents
    AED::SubscribedEvents{
      ART::Events::Request => 30,
    }
  end

  def initialize(@session_storage : SessionStorage)
  end

  def call(event : ART::Events::Request, dispatcher : AED::EventDispatcherInterface) : Nil
    cookies = HTTP::Cookies.from_client_headers event.request.headers
    token = cookies["example_session"]?.try &.value

    if token && Session.valid? token
      session = Session.find?(token)
      user = User.find? session.username
      Log.context.set username: user.username
      @session_storage.user = user
      @session_storage.session = session
    end
  end
end

###############
# Controllers #
###############

class IndexController < ART::Controller
  @[ARTA::Get("/")]
  def index : ART::Response
    html = render_view "index.html"
    ART::Response.new html, headers: HTTP::Headers{"content-type" => MIME.from_extension(".html")}
  end
end

@[ADI::Register(public: true)]
class AuthController < ART::Controller
  def initialize(@session : SessionStorage)
  end

  @[ARTA::Get("/login")]
  def index : ART::Response
    html = render_view "login.html"
    ART::Response.new html, headers: HTTP::Headers{"content-type" => MIME.from_extension(".html")}
  end

  @[ARTA::Post("/login")]
  @[ARTA::RequestParam("username")]
  @[ARTA::RequestParam("password")]
  def login(username : String, password : String) : ART::RedirectResponse
    # Authenticate user
    user = User.find? username
    raise ART::Exceptions::Forbidden.new "The username or password is incorrect" unless user && user.verify_password password

    Log.info { "#{username} logged in" }
    session = Session.new user.username
    session.save
    cookie = HTTP::Cookie.new "example_session", session.token
    ART::RedirectResponse.new "/secret", headers: HTTP::Headers{"Set-Cookie" => cookie.to_cookie_header}
  end

  @[ARTA::Get("/logout")]
  def logout : ART::RedirectResponse
    user = @session.user
    session = @session.session
    return ART::RedirectResponse.new "/" unless user && session

    # Logout
    Log.info { "#{user.username} logged out" }
    session.delete
    cookie = HTTP::Cookie.new "example_session", "", expires: Time.unix(0)
    ART::RedirectResponse.new "/", headers: HTTP::Headers{"Set-Cookie" => cookie.to_cookie_header}
  end
end

@[ADI::Register(public: true)]
class SecretController < ART::Controller
  def initialize(@session : SessionStorage)
  end

  @[ARTA::Get("/secret")]
  def secret : ART::Response
    user = @session.user
    raise ART::Exceptions::Forbidden.new "not logged in" unless user
    raise ART::Exceptions::Forbidden.new "Not an admin" unless user.admin

    Log.info { "#{user.username} accessed the secret area" }
    html = render_view "secret.html"
    ART::Response.new html, headers: HTTP::Headers{"content-type" => MIME.from_extension(".html")}
  end
end

# Start Server
##############
ART.run
