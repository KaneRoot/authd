require "option_parser"

require "ipc"
require "yaml"

require "baguette-crystal-base"

require "../src/libauth.cr"

class Context
	class_property simulation    = false  # do not perform the action

	class_property authd_login   = "undef" # undef authd user
	class_property authd_pass    = "undef" # undef authd user password
	class_property shared_key    = "undef" # undef authd user password

	# # Properties to select what to display when printing a deal.
	# class_property print_title        = true
	# class_property print_description  = true
	# class_property print_owner        = true
	# class_property print_nb_comments  = true

	class_property command       = "not-implemented"

	class_property user_profile  : Hash(String,JSON::Any)?
	class_property phone         : String?
	class_property email         : String?

	# Will be parsed later, with a specific parser.
	class_property args               : Array(String)? = nil
end

require "./better-parser"

class Actions

	def self.ask_password
		STDOUT << "password: "
		STDOUT << `stty -echo`
		STDOUT.flush
		password = STDIN.gets.try &.chomp

		STDOUT << '\n'
		STDOUT << `stty echo`

		password
	end

	def self.ask_something(str : String) : String?
		STDOUT << "#{str} "
		STDOUT.flush
		answer = STDIN.gets.try &.chomp
		answer
	end


	property the_call = {} of String => Proc(Nil)
	property authd : AuthD::Client

	def initialize(@authd)
		@the_call["user-add"]          = ->user_add
		@the_call["user-mod"]          = ->user_mod
		@the_call["user-registration"] = ->user_registration  # Do not require admin priviledges.
		@the_call["user-delete"]       = ->user_deletion      # Do not require admin priviledges.
		@the_call["user-get"]          = ->user_get           # Do not require authentication.
		@the_call["user-validation"]   = ->user_validation    # Do not require authentication.
		@the_call["user-recovery"]     = ->user_recovery      # Do not require authentication.
		@the_call["user-search"]       = ->user_search        # Do not require authentication.

		@the_call["permission-set"]   = ->permission_set
		@the_call["permission-check"] = ->permission_check

	end

	#
	# For all functions: the number of arguments is already tested.
	#

	def user_add
		puts "User add!!!"
		args = Context.args.not_nil!
		login, email, phone = args[0..2]
		profile = Context.user_profile

		password = Actions.ask_password
		exit 1 unless password

		pp! authd.add_user login, password.not_nil!, email, phone, profile: profile
	rescue e : AuthD::Exception
		puts "error: #{e.message}"
	end

	def user_registration
		args = Context.args.not_nil!
		login, email, phone = args[0..2]
		profile = Context.user_profile

		password = Actions.ask_password
		exit 1 unless password

		res = authd.register login, password.not_nil!, email, phone, profile: profile
		puts res
	rescue e
		puts "error: #{e.message}"
	end

	# TODO
	def user_mod
		args = Context.args.not_nil!
		userid = args[0]

		password : String? = nil

		should_ask_password = Actions.ask_something "Should we change the password (Yn) ?" || "n"
		case should_ask_password
		when /y/i
			Baguette::Log.debug "Ok let's change the password!"
			password = Actions.ask_password
			exit 1 unless password
		else
			Baguette::Log.debug "Ok no change in password."
		end

		email = Context.email
		phone = Context.phone

		Baguette::Log.error "This function shouldn't be used for now."
		Baguette::Log.error "It is way too cumbersome."

        # res = authd.add_user login, password, email, phone, profile: profile
        # puts res
	end

	def user_deletion
		args = Context.args.not_nil!
		userid = args[0].to_i

		# Check if the request comes from an admin or the user.
		res = if Context.shared_key.nil?
			authd.delete userid, Context.authd_login, Context.authd_pass
		else
			authd.delete userid, Context.shared_key
		end

		puts res
	end

	def user_validation
		args = Context.args.not_nil!
		login, activation_key = args[0..1]
		pp! authd.validate_user login, activation_key
	end
	def user_search
		args = Context.args.not_nil!
		login = args[0]
        pp! authd.search_user login
	end
	def user_get
		args = Context.args.not_nil!
		login = args[0]
		pp! authd.get_user? login
	end
	def user_recovery
		args = Context.args.not_nil!
		login, email = args[0..1]
        pp! authd.ask_password_recovery login, email
	end

	def permission_check
		args = Context.args.not_nil!
		user, application, resource = args[0..2]
		# pp! user, application, resource

		res = @authd.check_permission user.to_i, application, resource
		puts res
	end

	def permission_set
		args = Context.args.not_nil!
		user, application, resource, permission = args[0..3]
		# pp! user, application, resource, permission

		perm = AuthD::User::PermissionLevel.parse(permission)
		res = @authd.set_permission user.to_i, application, resource, perm
		puts res
	end
end

def main

	# Authd connection.
	authd = AuthD::Client.new
	authd.key = Context.shared_key if Context.shared_key != "undef"

	# Authd token.
	# FIXME: not sure about getting the token, it seems not used elsewhere.
	# If login == pass == "undef": do not even try.
	#unless Context.authd_login == Context.authd_pass && Context.authd_login == "undef"
	#	login = Context.authd_login
	#	pass  = Context.authd_pass
	#	token = authd.get_token? login, pass
	#	raise "cannot get a token" if token.nil?
	#	# authd.login token
	#end

	actions = Actions.new authd

	# Now we did read the intent, we should proceed doing what was asked.
	begin
		actions.the_call[Context.command].call
	rescue e
		Baguette::Log.info "The command is not recognized (or implemented)."
	end

	# authd disconnection
	authd.close
rescue e
	Baguette::Log.info "Exception: #{e}"
end


# Command line:
#   tool [options] command [options-for-command]

main
