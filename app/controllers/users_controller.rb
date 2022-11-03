class UsersController < ApplicationController
    skip_before_action :authorized, only: [:create]

    def create 
        @user = User.create(user_params)
        if @user.valid?
            @token = encode_token(user_id: @user.id)
            render json: {
                user: UserSerializer.new(@user),
                token: @token
            }, status: :created

        else
            render json: { errors: @user.errors.full_messages }, status: :unprocessable_entity
        end
    end

    def me 
        render json: current_user, status: :ok
    end

    private

    def user_params 
        params.permit(:username, :password, :bio)
    end
end
