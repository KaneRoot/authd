class AuthD::Request
	IPC::JSON.message SearchUser, 13 do
		property user : String

		def initialize(@user)
		end

		def handle(authd : AuthD::Service)
			pattern = Regex.new @user, Regex::Options::IGNORE_CASE

			matching_users = Array(AuthD::User::Public).new

			users = authd.users.to_a
			users.each do |u|
				if pattern =~ u.login || u.profile.try do |profile|
						full_name = profile["full_name"]?
						if full_name.nil?
							false
						else
							pattern =~ full_name.as_s
						end
					end
					Baguette::Log.debug "#{u.login} matches #{pattern}"
					matching_users << u.to_public
				else
					Baguette::Log.debug "#{u.login} doesn't match #{pattern}"
				end
			end

			Response::MatchingUsers.new matching_users
		end
	end
	AuthD.requests << SearchUser
end
