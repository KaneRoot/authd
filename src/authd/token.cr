require "json"

class AuthD::Token
	include JSON::Serializable

	property login : String
	property uid   : Int32

	def initialize(@login, @uid)
	end

	def to_h
		{
			:login => login,
			:uid   => uid
		}
	end

	def to_s(key)
		JWT.encode to_h, key, JWT::Algorithm::HS256
	end

	def self.from_s(key, str)
		payload, meta = JWT.decode str, key, JWT::Algorithm::HS256

		self.new payload["login"].as_s, payload["uid"].as_i
	end
end

