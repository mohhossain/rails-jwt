# Rails JWT authentication

A JSON web token(JWT) is a JSON Object that is used to securely transfer information between two parties. JWT is widely used for securely authenticate and authorize user from the client in a REST API. In this post, I will go over step by step how to implement authentication using JWT in a rails API.

### The gems we need:

```jsx
gem 'bcrypt', '~> 3.1', '>= 3.1.12’

gem 'jwt', '~> 2.5’

gem 'rack-cors'

gem 'active_model_serializers', '~> 0.10.12’
```

After adding the gemfile run `bundle install`

### Create the routes

```ruby
  post "/users", to: "users#create"
  get "/me", to: "users#me"
  post "/auth/login", to: "auth#login"
```

We will sign up new users making a POST request to /users. An existing user can log in by making a post request to “/auth/login” and a user can access user data by making a GET request to “/me”. We need 3 routes to the least, more routes can be added later as we go.

### Add CORS

```ruby
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins '*'

    resource '*',
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head]
  end
end
```

Cross-Origin Resource Sharing (CORS) is a middleware that will accept requests to the API from only one client URL. The client URL that we want to allow to make a request will go into the `origins`. We set \* origins, for now, that will allow anyone to make requests to our API for now.

### Create the user model:

```ruby
rails g model user username password_digest bio --no-test-framework
```

Add the `has_secure_password` macro in the user model and validation for the username:

```ruby
class User < ApplicationRecord
    has_secure_password
    validates :username, uniqueness: true
end
```

`has_secure_password` is a bcrypt method that encrypts the password for each user. For this method to work we add `password_digest` field to our database table. However, when we make a post request to our server we send `password`. Bcrypt handles the rest for us.

Example request:

```ruby
fetch('URL/auth/login',{
method: POST,
headers: {
	'Content-type': 'application/json'
},
body: {
	username: 'randomUserName',
	password: 'ask^dsk34'
})

```

## Adding JWT to our API

**JSON Web Tokens are an open, industry-standard RFC 7519 method for representing claims securely between two parties.** A JWT token looks like this: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/98cw53jjoju4gu5p0nze.png)

Source - [JWT.io](https://jwt.io/)

It has three parts. The first part is the header that contain the algorithm and token type. The second part is the payload, the data we want to store in the token. The third part is the signature, which contains the _secret key_. We are going to generate JWT tokens from the application_controller.rb

```ruby
class ApplicationController < ActionController::API

	def encode_token(payload)
		JWT.encode(payload, 'hellomars1211')
	end

	def decoded_token
		header = request.headers['Authorization']
		if header
			token = header.split(" ")[1]
			begin
				JWT.decode(token, 'hellomars1211')
			rescue JWT::DecodeError
				nil
			end
		end
	end

end
```

The `encode_token` method takes the payload as an argument. We will pass the user id as a payload. Then we call the `JWT.encode(payload, 'hellomars1211')` method to encode our token. Our payload will be the user id which then we can use to find the correct user. Notice that we pass a string: `'hellomars1211'`, along with the payload as an argument, which will be our secret key, that we’ll also use to decode our token. A secret key can be any combination of chars, symbols, numbers, etc. We will call the `decoded_token` method to decode a JWT token.

Whenever we make a request to a protected route or resource we pass the JWT token along with our data in the request, in the Authorization header using the Bearer schema. An example request:

```ruby
fetch("URL/me", {
  method: "GET",
  headers: {
    Authorization: `Bearer <token>`,
  },
});
```

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/0qrlfnflir3f2glr991f.png)

We access the token from the header and decode the token using `JWT.decode(token, 'hellomars1211', true, algorithm: 'HS256')` method, we also need to pass the secret key in order to decode the token.

We can now access the `user.id` from the decoded token. We will create a method `current_user` that takes the user id from the decoded token and find the user using the same user id. This will give us the user that is currently logged in. We will create another method `authorized` to check if we have a current_user that is logged in.

```ruby
def current_user
    if decoded_token
        user_id = decoded_token[0]['user_id']
        @user = User.find_by(id: user_id)
    end
end

def authorized
    unless !!current_user
    render json: { message: 'Please log in' }, status: :unauthorized
    end
end
```

Finally we will add a `before_action` rule to the controller that will call the `authorized` method before doing anything and check if the user is logged in. For any unauthorized request we will render a message: `Please log in`. This is what our application_controller will look like:

```ruby
*app/controllers/application_controller.rb*

class ApplicationController < ActionController::API
    before_action :authorized

    def encode_token(payload)
        JWT.encode(payload, 'hellomars1211')
    end

    def decoded_token
        header = request.headers['Authorization']
        if header
            token = header.split(" ")[1]
            begin
                JWT.decode(token, 'hellomars1211', true, algorithm: 'HS256')
            rescue JWT::DecodeError
                nil
            end
        end
    end

    def current_user
        if decoded_token
            user_id = decoded_token[0]['user_id']
            @user = User.find_by(id: user_id)
        end
    end

    def authorized
        unless !!current_user
        render json: { message: 'Please log in' }, status: :unauthorized
        end
    end

end
```

### Create the users_controller

```ruby
rails g controller users
```

In the user controller, we will create an action for creating or signing up a new user. We will also create a token if a user signs up with valid data and send the token along with the response, this will make the user to be logged in right away when they sign up for our app. We will handle the sign up function in the create method inside the users_controller.rb.

```ruby
class UsersController < ApplicationController
    rescue_from ActiveRecord::RecordInvalid, with: :handle_invalid_record

    def create
        user = User.create!(user_params)
        @token = encode_token(user_id: user.id)
        render json: {
            user: UserSerializer.new(user),
            token: @token
        }, status: :created
    end

    private

    def user_params
        params.permit(:username, :password, :bio)
    end

    def handle_invalid_record(e)
            render json: { errors: e.record.errors.full_messages }, status: :unprocessable_entity
    end
end
```

We serialized our data to only return the user id, username, and bio. It wouldn’t make sense for us to return the password to the client and also the password is encrypted in our database.

```ruby
class UserSerializer < ActiveModel::Serializer
  attributes :id, :username, :bio
end
```

Now, remember when we added the `before_action` rule to the application_controller? That will prevent us creating a new user if we are logged in. But that doesn’t make any sense. How can we log in when we didn’t even sign up yet or how can we log in when we can’t create a new user at all? Well, in order for us to bypass authorization we will add a `skip_before_action` to the user controller and make exception for only the `create` method. This will allow us to skip the authorization if we want to sign up a new user.

Also, we will create method `me` to get the profile of the user that will return the `current_user` that we set in the application_controller.

```ruby
*app/controllers/users_controller.rb*

class UsersController < ApplicationController
    skip_before_action :authorized, only: [:create]
    rescue_from ActiveRecord::RecordInvalid, with: :handle_invalid_record

    def create
        user = User.create!(user_params)
        @token = encode_token(user_id: user.id)
        render json: {
            user: UserSerializer.new(user),
            token: @token
        }, status: :created
    end

    def me
        render json: current_user, status: :ok
    end

    private

    def user_params
        params.permit(:username, :password, :bio)
    end

    def handle_invalid_record(e)
            render json: { errors: e.record.errors.full_messages }, status: :unprocessable_entity
    end
end
```

Our sign-up is ready. Let’s try making some request it in the postman:

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/vml4gdejke9wadg18cec.png)

Let’s gooooooooooo!! Oh, wait! What else are we missing? The most important part of the auth: the **LOGIN**!

To implement login we will create a new controller and we will call it auth_controller.

```ruby
rails g controller auth
```

```ruby
*app/controllers/auth_controller.rb*

class AuthController < ApplicationController

    skip_before_action :authorized, only: [:login]
    rescue_from ActiveRecord::RecordNotFound, with: :handle_record_not_found

    def login
        @user = User.find_by!(username: login_params[:username])
        if @user.authenticate(login_params[:password])
            @token = encode_token(user_id: @user.id)
            render json: {
                user: UserSerializer.new(@user),
                token: @token
            }, status: :accepted
        else
            render json: {message: 'Incorrect password'}, status: :unauthorized
        end

    end

    private

    def login_params
        params.permit(:username, :password)
    end

    def handle_record_not_found(e)
        render json: { message: "User doesn't exist" }, status: :unauthorized
    end
end
```

In the `login` method we are first finding the user with the username, if the user is not found we return an error message: `"User doesn't exist"`. After we find the user we authenticate the user with the password using bcrypt’s authenticate method. Once the authentication is complete we create a token for the user and return the user along with token. In case the authentication is failed we return an error message: `'Incorrect password'`. We also added the `skip_before_action :authorized, only: [:login]` here just like for the create method in the users controller.

Let’s make some calls in postman:

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/kavg7ib9u5kx1a914dqi.png)

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/pppzpi2be570gkce1cox.png)

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/23mu68nzg2ychrui99mm.png)

**Our auth is complete.**

User authentication is 3 fold. At first we validate the data, then we authenticate the user with correct username, and password, and finally we authorize the user.

### Validation—————>Authentication————>Authorization

We cannot build a logout function if we authenticate using JWT. The JWT library doesn’t come with a destroy method for the token. So, how can we log out? That has to be handled in the client. If we have a react client, we can store the token when we login in the localStorage and remove it from the localStorage if we want to log out.

```ruby
fetch("http://localhost:3000/auth/login/", {
      method: "POST",
      headers: {
        "Content-type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        password: password,
      }),
    })
      .then((res) => res.json())
      .then((data) => {
        localStorage.setItem("jwt", data.jwt);
      })
```

And we simply remove the jwt token from the localStorage to logout:

```ruby
localStorage.removeItem("jwt")
```
