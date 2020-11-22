module AuthD
	class Exception < ::Exception
	end

	class UserNotFound < ::Exception
	end

	class AuthenticationInfoLacking < ::Exception
	end

	class AdminAuthorizationException < ::Exception
	end
end
