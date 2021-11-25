#include <openssl/hmac.h>

namespace zindorsky {
namespace crypto {

//RAII wrapper for OpenSSL HMAC API
class hmac {
public:
	enum { digest_sz = 32 };

	hmac(void const* key, int length) noexcept
		: hmac_{HMAC_CTX_new()}
	{
		HMAC_Init_ex(hmac_, key, length, EVP_sha256(), nullptr);
	}

	hmac( hmac const& rhs ) noexcept
		: hmac_{HMAC_CTX_new()}
	{
		HMAC_CTX_copy(hmac_, const_cast<hmac&>(rhs).hmac_);
	}

	hmac & operator = (hmac const& rhs) noexcept
	{
		if(this != &rhs) {
			HMAC_CTX_copy(hmac_, const_cast<hmac&>(rhs).hmac_);
		}
		return *this;
	}

	hmac( hmac && rhs ) noexcept
	{
		hmac_ = rhs.hmac_;
		rhs.hmac_ = nullptr;
	}

	hmac & operator = (hmac && rhs) noexcept
	{
		if(this != &rhs) {
			if(hmac_) {
				HMAC_CTX_free(hmac_);
			}
			hmac_ = rhs.hmac_;
			rhs.hmac_ = nullptr;
		}
		return *this;
	}

	~hmac()
	{
		if(hmac_) {
			HMAC_CTX_free(hmac_);
		}
	}

	//HMAC operations:
	void reset()
	{
		HMAC_Init_ex(hmac_, nullptr, 0, nullptr, nullptr);
	}

	void update( void const* data, std::size_t length )
	{
		HMAC_Update(hmac_, static_cast<byte const*>(data), length);
	}

	void final( byte * digest )
	{
		HMAC_Final(hmac_, digest, nullptr);
	}

private:
	HMAC_CTX* hmac_;
};

class hmac_verification_failure : public std::runtime_error {
public:
	hmac_verification_failure() : std::runtime_error("HMAC verification failure.") {}
};

}} //namespace

