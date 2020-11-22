class AuthD::Request
	IPC::JSON.message EditProfile, 14 do
		property token : String
		property new_profile : Hash(String, JSON::Any)

		def initialize(@token, @new_profile)
		end

		def handle(authd : AuthD::Service, event : IPC::Event::Events)
			user = authd.get_user_from_token @token

			return Response::Error.new "invalid user" unless user

			new_profile = @new_profile

			profile = user.profile || Hash(String, JSON::Any).new

			authd.configuration.read_only_profile_keys.each do |key|
				if new_profile[key]? != profile[key]?
					return Response::Error.new "tried to edit read only key"
				end
			end

			user.profile = new_profile

			authd.users_per_uid.update user.uid.to_s, user

			Response::User.new user.to_public
		end
	end
	AuthD.requests << EditProfile

	# Same as above, but doesn’t reset the whole profile, only resets elements
	# for which keys are present in `new_profile`.
	IPC::JSON.message EditProfileContent, 15 do
		property token      : String? = nil

		property shared_key : String? = nil
		property user : Int32 | String | Nil

		property new_profile : Hash(String, JSON::Any)

		def initialize(@shared_key, @user, @new_profile)
		end
		def initialize(@token, @new_profile)
		end

		def handle(authd : AuthD::Service, event : IPC::Event::Events)
			user = if token = @token
				u = authd.get_user_from_token token
				raise UserNotFound.new unless u
				u
			elsif shared_key = @shared_key
				raise AdminAuthorizationException.new if shared_key != authd.configuration.shared_key

				u = @user
				raise UserNotFound.new unless u

				u = if u.is_a? Int32
					authd.users_per_uid.get? u.to_s
				else
					authd.users_per_login.get? u
				end
				raise UserNotFound.new unless u

				u
			else
				raise AuthenticationInfoLacking.new
			end

			new_profile = user.profile || Hash(String, JSON::Any).new

			unless @shared_key
				authd.configuration.read_only_profile_keys.each do |key|
					if @new_profile.has_key? key
						return Response::Error.new "tried to edit read only key"
					end
				end
			end

			@new_profile.each do |key, value|
				new_profile[key] = value
			end

			user.profile = new_profile

			authd.users_per_uid.update user.uid.to_s, user

			Response::User.new user.to_public
		end
	end
	AuthD.requests << EditProfileContent
end
