#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <openssl/crypto.h>

namespace secure
{
    // from bitcoin's allocator.h
    template<typename T>
    struct zero_after_free_allocator : public std::allocator<T>
    {
        // MSVC8 default copy constructor is broken
        typedef std::allocator<T> base;
        typedef typename base::size_type size_type;
        typedef typename base::difference_type  difference_type;
        typedef typename base::pointer pointer;
        typedef typename base::const_pointer const_pointer;
        typedef typename base::reference reference;
        typedef typename base::const_reference const_reference;
        typedef typename base::value_type value_type;

        zero_after_free_allocator() throw() {}
        zero_after_free_allocator(const zero_after_free_allocator& a) throw() : base(a) {}
        template <typename U>
        zero_after_free_allocator(const zero_after_free_allocator<U>& a) throw() : base(a) {}
        ~zero_after_free_allocator() throw() {}
        template<typename _Other> struct rebind
        { typedef zero_after_free_allocator<_Other> other; };

        void deallocate(T* p, std::size_t n)
        {
            if (p != NULL)
                OPENSSL_cleanse(p, sizeof(T) * n);
            std::allocator<T>::deallocate(p, n);
        }
    };

    typedef std::basic_string<char, std::char_traits<char>, zero_after_free_allocator<char> > string;
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > secret;
}

bool encryptKey(const secure::secret& keyData, const secure::string& strPassword, std::vector<unsigned char>& salt, int& nDeriveIterations, std::vector<unsigned char>& cryptedKey);
bool decryptKey(const std::vector<unsigned char>& cryptedKey, const secure::string& strPassword, const std::vector<unsigned char>& salt, int nDeriveIterations, secure::secret& decryptedKey);


#endif // ENCRYPTION_H
