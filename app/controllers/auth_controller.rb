class AuthController < ApplicationController

    skip_before_action :authorized, only: [:login]

    def login 
        @user = User.find_by(username: login_params[:username])
        if @user && @user.authenticate(login_params[:password])
            @token = encode_token(user_id: @user.id)
            render json: {
                user: UserSerializer.new(@user),
                token: @token
            }, status: :accepted

        else
            render json: {message: "Invalid Username or password"}, status: :unauthorized
        end

    end

    private 

    def login_params 
        params.permit(:username, :password)
    end
end
