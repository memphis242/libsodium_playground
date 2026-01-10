// Headers
// Standard Library Headers
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
// Error Handling and Assertions
#include <errno.h>
#include <assert.h>
// System Headers
#include <signal.h>
#ifndef NDEBUG
#include <sys/resource.h> // to setrlimit() on RLIMIT_CORE
#endif
// 3rd Party Libs
#include <sodium.h>

/*** Local Definitions ***/
#define ARRLEN(arr) ( sizeof(arr) / sizeof(arr[0]) )

enum MAINRC
{
   MAINRC_PRINTF_FAILURE = -2,
   MAINRC_SODIUM_INIT_FAILURE = -1,
   MAINRC_GOOD = 0,
   /* Bitfield from here on out */
   MAINRC_SIGACTION_CFG_FAILURE = 0x01,
};

enum UserInputRC
{
   UIRC_GOOD = 0,
   UIRC_EOF_OR_IO = 1,
   UIRC_TOO_LONG = 2,
};

enum ReadFileRC
{
   RFRC_GOOD = 0,
   RFRC_INVALID_FILE = 1,
   RFRC_FILE_NOT_READABLE = 2,
   RFRC_BUF_TOO_SMALL = 3,
};

struct PGCmd
{
   const char * cmd;
   const char * desc;
   // TODO: void (*cb)(void);
};

/* Local Constants */
constexpr size_t MAX_STRING_SZ = 10'000;
constexpr char SESSION_FILE_EXT[] = ".sp.session";

/* Local Variables */
static volatile sig_atomic_t bUserEndedSession = false;

struct PGCmd PGCmds[] =
{
   { "load",       "Load a previous play session from file" },
   { "save",       "Save current play session to file" },
   { "ls",         "List the session files in the current directory and /var/TBD" },
   { "newmsg",     "Create a new msg or replace existing one" },
   { "printmsg",   "Print the existing msg" },
   { "newpass",    "Create a new msg or replace existing one" },
   { "printpass",  "Print the existing passphrase" },
   { "printkey",   "Print the key derived from the passphrase" },
   { "verifypass", "Prompt user for passphrase and verify match against stored hash of passphrase" },
   { "encrypt",    "Encrypt the msg using a symmetric encryption with the key" },
   { "decrypt",    "Decrypt the ciphertext using a symmetric encryption with the key" },
   { "printctxt",  "Print the ciphertext from a previous encryption" },
   { "hextob64",   "Translate hex encoding to a base64 one" },
   { "b64tohex",   "Translate base64 encoding to a hex one" },
   { "quit",       "Get out of the playground" },
   { "exit",       "Get out of the playground" },
   { "ctrl+d",     "Get out of the playground" },
};

/* Local Function Forward Declarations */
static void handleSIGINT(int signum);

[[nodiscard]]
static bool isNulTerminated(const char * const str);

static inline void toLowercase(char * const str);

[[nodiscard]]
static inline enum UserInputRC getUserInput(
      char * buf,
      size_t sz,
      bool makelowercase );

[[nodiscard]]
static inline enum ReadFileRC readFileIntoBuf(
      FILE * fp,
      char * buf,
      size_t bufsz );

/*** Main ***/
int main(void)
{
   int mainrc = MAINRC_GOOD;
   int sodiumrc = 0;
   int rc = 0; // system call return code
   bool boolrc = false; // internal calls
                        // TODO: Replace any "success" bools downstream /w this

   char * msg = nullptr;
   ptrdiff_t msgsz = 0;
   uint8_t * cipherblob = nullptr;
   ptrdiff_t cipherblobsz = 0;
   char * ciphertxt = nullptr; // base64 encoding of cipherblob
   ptrdiff_t ciphertxtsz = 0;
   char passphrase[50] = {0};
   uint8_t * key = nullptr;
   size_t keysz = 0;
   char * b64 = nullptr;
   size_t b64sz = 0;
   constexpr int b64variant = sodium_base64_VARIANT_ORIGINAL;
   constexpr char b64variantstr[] = "sodium_base64_VARIANT_ORIGINAL";
   char * hex = nullptr;
   size_t hexsz = 0;
   uint8_t * salt = nullptr;
   size_t saltsz = 0;

   char filecounter = '0'; // FIXME: Delete this once I come up with a better scheme later...

   sodiumrc = sodium_init();
   if ( sodiumrc < 0 )
   {
      fprintf( stderr,
               "Sodium failed to initialize correctly.\n"
               "sodium_init() returned: %d. Aborting...\n",
               sodiumrc );

      return MAINRC_SODIUM_INIT_FAILURE;
   }

#  ifndef NDEBUG
   struct rlimit core_rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
   rc = setrlimit( RLIMIT_CORE, &core_rlim );
   if ( rc != 0 )
   {
      (void)fprintf( stderr,
               "Warning: setrlimit() failed, so coredumps might not work.\n"
               "         Returned: %d, errno: %s (%d): %s\n",
               rc, strerrorname_np(errno), errno, strerror(errno) );
   }
#  endif

   struct sigaction sa_cfg = {0};
   sa_cfg.sa_flags |= SA_RESTART; // I'd like to make sure file I/O calls are restarted if interrupted
   sigemptyset(&sa_cfg.sa_mask);
   sa_cfg.sa_handler = handleSIGINT;
   rc = sigaction( SIGINT, &sa_cfg, nullptr /* old signal cfg */ );
   if ( rc != 0 )
   {
      (void)fprintf( stderr,
               "Warning: sigaction() failed to register interrupt signal handler.\n"
               "Returned: %d, errno: %s (%d): %s\n"
               "You won't be able to stop the program gracefully /w Ctrl+C, although \n"
               "Ctrl+C will still terminate the program.\n",
               rc, strerrorname_np(errno), errno, strerror(errno) );

      mainrc |= MAINRC_SIGACTION_CFG_FAILURE;
   }

   rc = printf("Welcome! This is the libsodium playground. Prepare to get salty...😃\n"
               "--------------------------------------------------------------------\n");
   if ( rc < ( (int)sizeof("Welcome! Let's play /w libsodium!😃\n") - 1 ) )
   {
      // Can't print, so we'll just exit /w a specific return code to alert user
      return MAINRC_PRINTF_FAILURE;
   }

   for ( size_t i=0; i < ARRLEN(PGCmds); ++i )
   {
      (void)printf( "%-15s : %s\n", PGCmds[i].cmd, PGCmds[i].desc );
   }

   constexpr size_t WHILE_LOOP_CAP = 1'000'000;
   size_t nreps = 0;
   while ( !bUserEndedSession && nreps++ < WHILE_LOOP_CAP )
   {
      char cmd[64];

      (void)printf("\nsalty playground> ");
      (void)fflush(stdout);

      enum UserInputRC uirc = getUserInput(cmd, sizeof cmd, true);
      if ( uirc == UIRC_EOF_OR_IO )
         break;
      else if ( uirc != UIRC_GOOD )
         continue;

      /****************************** Parse Cmds ******************************/
      // TODO: Use string hashing + switch-case instead of if-elseif

      /*
   char * msg = nullptr;
   ptrdiff_t msgsz = 0;
   uint8_t * cipherblob = nullptr;
   ptrdiff_t cipherblobsz = 0;
   char * ciphertxt = nullptr; // base64 encoding of cipherblob
   ptrdiff_t ciphertxtsz = 0;
   char passphrase[50] = {0};
   uint8_t * key = nullptr;
   size_t keysz = 0;
   char * b64 = nullptr;
   size_t b64sz = 0;
   constexpr int b64variant = sodium_base64_VARIANT_ORIGINAL;
   constexpr char b64variantstr[] = "sodium_base64_VARIANT_ORIGINAL";
   char * hex = nullptr;
   size_t hexsz = 0;
   uint8_t * salt = nullptr;
   size_t saltsz = 0;
      */

      if ( strcmp(cmd, "load") == 0 )
      {
         char sfile[256];

         (void)printf("Session file (absolute or relative): ");
         (void)fflush(stdout);

         (void)fprintf(stderr, "Not yet implemented: load\n");
      }

      else if ( strcmp(cmd, "save") == 0 )
      {
         char sfile[256]; // TODO: Fixed naming format

         (void)printf("Session file (absolute or relative): ");
         (void)fflush(stdout);

         (void)fprintf(stderr, "Not yet implemented: save\n");
      }

      else if ( strcmp(cmd, "ls") == 0 )
      {
         // TODO: ls - use dirent.h + opendir(), readdir(), closedir()
         (void)fprintf(stderr, "Not yet implemented: save\n");
      }

      else if ( strcmp(cmd, "newmsg") == 0 )
      {
         char buf[2048];

         (void)printf("Enter message: ");
         (void)fflush(stdout);

         uirc = getUserInput(buf, sizeof buf, false);
         if ( uirc == UIRC_EOF_OR_IO )
            break;
         else if ( uirc != UIRC_GOOD )
            continue;

         assert(isNulTerminated(buf));

         // Copy msg over to persistent space outside of this scope, including '\0'
         msgsz = (ptrdiff_t)(strlen(buf) + 1);
         // Override previous msg
         // FIXME: Use realloc()
         free(msg);
         msg = malloc( (size_t)(msgsz) * sizeof(char) );
         if ( msg == nullptr )
         {
            (void)fprintf( stderr,
                     "Error: Couldn't malloc() %ti bytes for a buffer for msg\n",
                     msgsz);
            continue;
         }
         (void)memcpy( msg, buf, (size_t)msgsz );

         (void)printf("Successfully received msg.\n");
      }

      else if ( strcmp(cmd, "printmsg") == 0 )
      {
         if ( msg == nullptr )
         {
            (void)fprintf(stderr, "No msg present. Aborting cmd...\n");
            continue;
         }

         assert(isNulTerminated(msg));

         (void)printf("%s\n", msg);
      }

      else if ( strcmp(cmd, "newpass") == 0 )
      {
         (void)printf("Note old encrypted content will remain!\n"
                      "New Passphrase: ");

         uirc = getUserInput( passphrase, sizeof passphrase, false );
         if ( uirc == UIRC_EOF_OR_IO )
            break;
         else if ( uirc != UIRC_GOOD )
            continue;

         assert( isNulTerminated(passphrase) );

         (void)printf("Successfully updated passphrase\n");

         // TODO: Provide choice for KDF + AEAD encryption algorithm + parameters...
         // FIXME: sodium_mlock() passphrase?
         //        See: https://doc.libsodium.org/doc/password_hashing/default_phf#notes

         (void)printf("Generating new encryption key using default libsodium KDF"
                      " for XChaCha20Poly1305_IETF AEAD cipher...\n");

         // We will override previous stores
         free(salt);
         free(key);

         saltsz = crypto_pwhash_SALTBYTES;
         salt = malloc(saltsz);
         if ( salt == nullptr )
         {
            (void)fprintf( stderr,
                     "Error: Couldn't malloc() %zu bytes for a buffer for salt\n",
                     saltsz);
            continue;
         }
         keysz = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
         key = malloc(keysz);
         if ( key == nullptr )
         {
            (void)fprintf( stderr,
                     "Error: Couldn't malloc() %zu bytes for a buffer for key\n",
                     keysz);
            continue;
         }

         randombytes_buf(salt, saltsz);

         // Print salt to console
         size_t salthexsz = saltsz * 2 + 1;
         char * salthex = malloc( salthexsz * sizeof(char) );
         if ( salthex == nullptr )
         {
            (void)fprintf( stderr,
                     "Error: Couldn't malloc() %zu bytes for a buffer for hex encoding of salt\n",
                     salthexsz);
            continue;
         }
         (void)sodium_bin2hex( salthex, salthexsz,
                               salt, saltsz );

         size_t saltb64sz = sodium_base64_ENCODED_LEN(saltsz, b64variant);
         char * saltb64 = malloc( saltb64sz * sizeof(char) );
         if ( saltb64 == nullptr )
         {
            (void)fprintf( stderr,
                     "Error: Couldn't malloc() %zu bytes for a buffer for base64 encoding of salt\n",
                     saltb64sz);
            // FIXME: Need to free previous allocations before continue'ing
            continue;
         }
         (void)sodium_bin2base64( saltb64, saltb64sz,
                                  salt, saltsz,
                                  b64variant );

         (void)printf("Using salt:\n"
                      "- hex: %s\n"
                      "- b64: %s\n",
                      salthex,
                      saltb64 );

         unsigned long long int opslimit = crypto_pwhash_OPSLIMIT_SENSITIVE;
         char opslimitstr[] = "crypto_pwhash_OPSLIMIT_SENSITIVE";
         size_t memlimit = crypto_pwhash_MEMLIMIT_SENSITIVE;
         char memlimitstr[] = "crypto_pwhash_MEMLIMIT_SENSITIVE";
         int alg = crypto_pwhash_ALG_DEFAULT;
         char algstr[] = "crypto_pwhash_ALG_DEFAULT";

         sodiumrc = crypto_pwhash( key, keysz,
                                   passphrase, strnlen(passphrase, sizeof passphrase),
                                   salt,
                                   opslimit, memlimit, alg );
         if ( sodiumrc != 0 )
         {
            (void)fprintf( stderr,
                     "Failed to create encryption key from KDF.\n"
                     "crypto_pwhash returned: %d\n",
                     sodiumrc );
            continue;
         }

         (void)printf("Successfully generated new encryption key.\n");

         // Save the hex encoding (both salt and key) for later printing
         hexsz= keysz * 2 + 1;
         hex = malloc( hexsz * sizeof(char) );
         if ( hex == nullptr )
         {
            (void)fprintf( stderr,
                     "Error: Couldn't malloc() %zu bytes for a buffer for hex encoding of key\n",
                     hexsz);
            continue;
         }
         (void)sodium_bin2hex( hex, hexsz,
                               key, keysz );

         // Same for base64 encoding
         b64sz= sodium_base64_ENCODED_LEN(keysz, b64variant);
         b64 = malloc( b64sz * sizeof(char) );
         if ( b64 == nullptr )
         {
            (void)fprintf( stderr,
                     "Error: Couldn't malloc() %zu bytes for a buffer for base64 encoding of key\n",
                     b64sz);
            continue;
         }
         (void)sodium_bin2base64( b64, b64sz,
                                  key, keysz,
                                  b64variant );

         assert(key != nullptr);
         assert(keysz > 0);
         assert(hex != nullptr);
         assert(hexsz > 0);
         assert(b64 != nullptr);
         assert(b64sz > 0);
         assert(isNulTerminated(hex));
         assert(isNulTerminated(b64));

         (void)printf("- hex: %s\n", hex);
         (void)printf("- b64: %s\n", b64);

         (void)printf("Writing key data to files...\n");

         // Write the raw binary key to a file for later viewing
         // TODO: Figure out how you should store salt, KDF alg, and KDF parms
         char testkey_filename[ sizeof("./testkey") + 1 + sizeof(".bin") ] = {0};
         (void)strcat(testkey_filename, "./testkey");
         (void)strcat(testkey_filename, (char[]){filecounter, '\0'});
         (void)strcat(testkey_filename, ".bin");
         assert(isNulTerminated(testkey_filename));

         FILE * fd = fopen(testkey_filename, "wb");
         if ( fd == nullptr )
         {
            // FIXME: (void) all fprintf() returns
            fprintf( stderr,
               "Error: Failed to open file %s\n"
               "fopen() returned nullptr, errno: %s (%d): %s\n",
               testkey_filename,
               strerrorname_np(errno), errno, strerror(errno) );

            continue;
         }

         {
            size_t nwritten = fwrite( key,
                                      1 /* element sz */,
                                      keysz /* n items */,
                                      fd );
            if ( nwritten != keysz )
            {
               fprintf( stderr,
                  "Error: Failed to write all the bytes of the key to %s\n"
                  "Wrote only %zu bytes out of %zu (%zu bytes short)\n"
                  "errno: %s (%d): %s\n",
                  testkey_filename,
                  nwritten, keysz, keysz - nwritten,
                  strerrorname_np(errno), errno, strerror(errno) );
            }
         }

         rc = fclose(fd);
         if ( rc != 0 )
         {
            assert(errno != EINTR); // Assert this because I should have set the
                                    // SA_RESTART flag for the SIGINT handler
            // TODO: Consider checking if errno was EINTR?
            fprintf( stderr,
               "Error: Failed to open file %s\n"
               "fopen() returned nullptr, errno: %s (%d): %s\n",
               testkey_filename,
               strerrorname_np(errno), errno, strerror(errno) );

            continue;
         }

         // Repeat for text encodings
         assert(isNulTerminated(testkey_filename));
         testkey_filename[ strlen(testkey_filename) - sizeof("bin") + 1 ] = '\0';
         (void)strcat(testkey_filename, "hex");

         fd = fopen(testkey_filename, "w");
         if ( fd == nullptr )
         {
            fprintf( stderr,
               "Error: Failed to open file %s\n"
               "fopen() returned nullptr, errno: %s (%d): %s\n",
               testkey_filename,
               strerrorname_np(errno), errno, strerror(errno) );

            continue;
         }

         {
            int nwritten = fprintf( fd,
                              "Original Passphrase: %s\n"
                              "Salt: %s\n"
                              "KDF Algorithm: %s (%d)\n"
                              "KDF Ops Limit: %s (%llu)\n"
                              "KDF Mem LImit: %s (%zu)\n"
                              "Key Encoding: %s\n",
                              passphrase, salthex,
                              algstr, alg,
                              opslimitstr, opslimit,
                              memlimitstr, memlimit,
                              hex );

            if ( nwritten < 0 )
            {
               fprintf( stderr,
                  "Error: fprintf() of hex encodings to %s failed\n"
                  "errno: %s (%d): %s\n",
                  testkey_filename,
                  strerrorname_np(errno), errno, strerror(errno) );
            }
         }
         free(salthex);

         rc = fclose(fd);
         if ( rc != 0 )
         {
            assert(errno != EINTR);
            // TODO: Consider checking if errno was EINTR?
            fprintf( stderr,
               "Error: Failed to open file %s\n"
               "fopen() returned nullptr, errno: %s (%d): %s\n",
               testkey_filename,
               strerrorname_np(errno), errno, strerror(errno) );

            continue;
         }

         testkey_filename[ strlen(testkey_filename) - sizeof("hex") + 1 ] = '\0';
         (void)strcat(testkey_filename, "b64");

         fd = fopen(testkey_filename, "w");
         if ( fd == nullptr )
         {
            fprintf( stderr,
               "Error: Failed to open file %s\n"
               "fopen() returned nullptr, errno: %s (%d): %s\n",
               testkey_filename,
               strerrorname_np(errno), errno, strerror(errno) );

            continue;
         }

         {
            int nwritten = fprintf( fd,
                              "Original Passphrase: %s\n"
                              "Salt: %s\n"
                              "KDF Algorithm: %s (%d)\n"
                              "KDF Ops Limit: %s (%llu)\n"
                              "KDF Mem LImit: %s (%zu)\n"
                              "Key Encoding: %s\n",
                              passphrase, saltb64,
                              algstr, alg,
                              opslimitstr, opslimit,
                              memlimitstr, memlimit,
                              b64 );

            if ( nwritten < 0 )
            {
               fprintf( stderr,
                  "Error: fprintf() of base64 encodings to %s failed\n"
                  "errno: %s (%d): %s\n",
                  testkey_filename,
                  strerrorname_np(errno), errno, strerror(errno) );
            }
         }
         free(saltb64);

         rc = fclose(fd);
         if ( rc != 0 )
         {
            assert(errno != EINTR);
            // TODO: Consider checking if errno was EINTR?
            fprintf( stderr,
               "Error: Failed to open file %s\n"
               "fopen() returned nullptr, errno: %s (%d): %s\n",
               testkey_filename,
               strerrorname_np(errno), errno, strerror(errno) );

            continue;
         }

         printf("Successfully wrote files\n");

         filecounter++;
      }

      else if ( strcmp(cmd, "printpass") == 0 )
      {
         if ( passphrase[0] == '\0' )
         {
            (void)fprintf(stderr, "No passphrase present. Aborting cmd...\n");
            continue;
         }

         assert(isNulTerminated(passphrase));

         (void)printf("Passphrase: %s\n", passphrase);
      }

      else if ( strcmp(cmd, "printkey") == 0 )
      {
         assert( (key != nullptr && keysz > 0)
                 || (key == nullptr && keysz == 0) );
         assert( (hex != nullptr && hexsz > 0)
                 || (hex == nullptr && hexsz == 0) );

         if ( key == nullptr )
         {
            (void)fprintf(stderr, "No key present. Aborting cmd...\n");
            continue;
         }

         if ( hex == nullptr )
         {
            (void)fprintf(stderr, "No hex encoding present, skipping.\n");
         }
         else
         {
            assert(isNulTerminated(hex));

            (void)printf("Hex: %s\n", hex);
         }

         if ( b64 == nullptr )
         {
            (void)fprintf(stderr, "No base64 encoding present, skipping.\n");
         }
         else
         {
            assert(isNulTerminated(hex));

            (void)printf("Base64: %s\n", b64);
         }
      }

      else if ( strcmp(cmd, "verifykey") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "verifypassphrase") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "encrypt") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "decrypt") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "printctxt") == 0 )
      {
         if ( ciphertxt == nullptr )
         {
            (void)fprintf(stderr, "Error: No cipher text present.\n");
            continue;
         }

         if ( !isNulTerminated(ciphertxt) )
         {
            (void)fprintf(stderr, "ciphertxt is not terminated. Aborting cmd...\n");
            continue;
         }
         (void)printf("%s\n", ciphertxt);
      }

      else if ( strcmp(cmd, "storemsg") == 0 )
      {
         if ( msg == nullptr )
         {
            (void)fprintf(stderr, "No msg present. Aborting cmd...\n");
            continue;
         }

         char fname[128] = {0};
         constexpr char FEXT[] = ".msg";
         const size_t maxbaselen = sizeof(fname) - sizeof(FEXT) + 1;
         
         (void)printf("Filename (/wo extension, < %zu chars): ",
                      maxbaselen);

         size_t whileloop_reps = 0;
         boolrc = false;

         while ( !boolrc && whileloop_reps++ < WHILE_LOOP_CAP )
            boolrc = getUserInput( fname, maxbaselen, false );

         assert( isNulTerminated(fname) );
         assert(whileloop_reps < WHILE_LOOP_CAP);
         assert( strlen(fname) <= maxbaselen );

         (void)strcat(fname, FEXT);

         FILE * fd = fopen(fname, "w");
         if ( fd == nullptr )
         {
            (void)fprintf( stderr,
                     "Error: Failed to open file %s\n"
                     "fopen() returned nullptr, errno: %s (%d): %s\n",
                     fname,
                     strerrorname_np(errno), errno, strerror(errno) );

            continue;
         }

         {
            int nwritten = fprintf(fd, "%s", msg);

            if ( nwritten < 0 )
            {
               (void)fprintf( stderr,
                        "Error: fprintf() of msg to %s failed\n"
                        "errno: %s (%d): %s\n",
                        fname,
                        strerrorname_np(errno), errno, strerror(errno) );
            }
            else
            {
               (void)printf("Successfully wrote msg to specified file.");
            }
         }
      }

      else if ( strcmp(cmd, "loadmsg") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "storeciphertxt") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "loadciphertxt") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "storecipherblob") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "loadcipherblob") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "bintob64") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "bintohex") == 0 )
      {
         // TODO
         (void)printf("Not implemented yet.\n");
      }

      else if ( strcmp(cmd, "hextob64") == 0 )
      {
         char hexbuf[1024] = {0};

         (void)printf("hex: ");
         (void)fflush(stdout);

         bool success = getUserInput(hexbuf, sizeof hexbuf, true);
         if ( !success )
            continue;
         assert(isNulTerminated(hexbuf));

         size_t hexlen = strlen(hexbuf);
         if ( (hexlen % 2) != 0 )
         {
            (void)fprintf( stderr,
                     "Invalid Encoding: Odd number of hex digits.\n"
                     "Please try again.\n" );
            continue;
         }

         uint8_t binbuf[ (hexlen + 1) / 2 ];
         const char * hexend = &hexbuf[0];
         size_t binlen;

         sodiumrc = sodium_hex2bin( binbuf, sizeof binbuf,
                                    hexbuf, hexlen,
                                    nullptr, // characters to ignore
                                    &binlen, &hexend );

         assert(hexend != nullptr);
         assert(binlen < hexlen);
         // sodium_hex2bin should succeed because a nonzero return means either
         // I provided too small a binbuf or hex_end wasn't provided, which is
         // a design issue to me.
         assert(sodiumrc == 0);
         if ( *hexend != '\0'
              || (binlen < (hexlen/2) || binlen > (hexlen+1)/2 ) )
         {
            (void)fprintf( stderr,
                     "Error: An invalid hex character was encountered: '%c' @ idx: %ti\n"
                     "Unable to properly decode. Aborting cmd...\n",
                     *hexend, (ptrdiff_t)(hexend - &hexbuf[0]) );

            continue;
         }

         size_t b64len = sodium_base64_ENCODED_LEN(binlen, b64variant);
         char b64buf[b64len];

         (void)sodium_bin2base64( b64buf, sizeof b64buf,
                                  binbuf, binlen,
                                  b64variant );

         assert(isNulTerminated(b64buf));

         (void)printf("b64: %s\n", b64buf);
      }

      else if ( strcmp(cmd, "b64tohex") == 0 )
      {
         char b64buf[1024] = {0};

         (void)printf("b64: ");
         (void)fflush(stdout);

         bool success = getUserInput(b64buf, sizeof b64buf, false);
         if ( !success )
            continue;
         assert(isNulTerminated(b64buf));

         size_t b64len = strlen(b64buf);
         if ( b64variant == sodium_base64_VARIANT_ORIGINAL
              && (b64len % 4) != 0 )
         {
            (void)fprintf( stderr,
                     "Invalid Encoding: Since standard base64 encoding is used\n"
                     "(i.e., /w padding), an encoding must be a multiple of 4\n"
                     "characters. Instead, %zu characters were encountered, which\n"
                     "is %zu more than the nearest multiple of 4 that is\n"
                     "less than %zu (%zu).\n",
                     b64len,
                     b64len % 4,
                     b64len, (b64len / 4) * 4 );

            continue;
         }

         uint8_t binbuf[ b64len * 3 / 4 + 1 ];
         const char * b64end = &b64buf[0];
         size_t binlen;

         sodiumrc = sodium_base642bin( binbuf, sizeof binbuf,
                                       b64buf, b64len,
                                       nullptr, // characters to ignore
                                       &binlen, &b64end,
                                       b64variant );

         assert(b64end != nullptr);
         assert(binlen < b64len);
         // sodium_hex2bin should succeed because a nonzero return means either
         // I provided too small a binbuf or hex_end wasn't provided, which is
         // a design issue to me.
         assert(sodiumrc == 0);
         if ( *b64end != '\0' )
         {
            (void)fprintf( stderr,
                     "Error: An invalid base64 character was encountered: '%c' @ idx: %ti\n"
                     "Unable to properly decode. Aborting cmd...\n",
                     *b64end, (ptrdiff_t)(b64end - &b64buf[0]) );
            continue;
         }

         size_t hexlen = binlen * 2 + 1;
         char hexbuf[hexlen];

         (void)sodium_bin2hex( hexbuf, sizeof hexbuf,
                               binbuf, binlen );

         assert(isNulTerminated(hexbuf));

         (void)printf("hex: %s\n", hexbuf);
      }

      else if ( strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0 )
      {
         bUserEndedSession = true;
         break;
      }

      else
      {
         (void)fprintf(stderr, "Invalid command: %s. Please try again.\n", cmd);
         continue;
      }
      
   }

   assert( nreps < WHILE_LOOP_CAP );

   // TODO: Graceful shutdown
   // Free any dynamically allocated buffers...
   free(msg);
   free(cipherblob);
   free(ciphertxt);
   free(key);
   free(salt);
   free(b64);
   free(hex);
   // Close any files that we opened...
   // TODO

   return mainrc;
}

static void handleSIGINT(int signum)
{
   (void)signum;

   bUserEndedSession = true;
}

static bool isNulTerminated(const char * const str)
{
   for ( size_t i = 0 ; i < MAX_STRING_SZ; ++i )
      if ( str[i] == '\0' )
         return true;

   return false;
}

static inline void toLowercase(char * const str)
{
   assert(str != nullptr);
   assert(isNulTerminated(str));

   for ( char * ptr = str; ptr != nullptr && *ptr != '\0'; ++ptr )
      *ptr = (char)tolower(*ptr); // Assume no EOF in string...
}

[[nodiscard]]
static inline enum UserInputRC getUserInput(
      char * buf,
      size_t sz,
      bool makelowercase)
{
   if ( fgets(buf, (int)sz, stdin) == nullptr )
   {
      // Either EOF encountered /wo other characters preceding it or I/O
      // interruption occured. Either way, time to exit gracefully.
      clearerr(stdin);
      printf("\nExiting command...\n");
      return UIRC_EOF_OR_IO;
   }

   // Replace newline /w null-termination
   char * newlineptr = memchr(buf, '\n', sz);
   if ( nullptr == newlineptr )
   {
      // There were more characters than the size of the input buffer to fgets()
      // Clear the remaining characters in stdin...
      int c;
      while ( (c = fgetc(stdin)) != '\n' && c != EOF );

      // Take this as an invalid input and request the user to try again.
      (void)fprintf( stderr,
               "Error: Too many characters in user input encountered.\n"
               "Please try again.\n" );

      return UIRC_TOO_LONG;
   }
   assert( newlineptr < (buf + sz) );
   *newlineptr = '\0';

   if ( makelowercase )
      toLowercase(buf);

   return UIRC_GOOD;
}

[[nodiscard]]
static inline enum ReadFileRC readFileIntoBuf(
      FILE * fp,
      char * buf,
      size_t bufsz )
{
   assert(fp != nullptr);
   assert(buf != nullptr);

   /* Assert that the file is valid */
   const int fd = fileno(fp);
   if ( fd < 0 )
   {
      (void)fprintf( stderr,
                     "Unable to get file descriptor for fp: %p\n"
                     "errno: %s (%d): %s\n",
                     (void *)fp,
                     strerrorname_np(errno), errno, strerror(errno) );

      return RFRC_INVALID_FILE;
   }

   // FIXME: Apparently, fcntl() and fopen() don't necessarily line up...
   //const int fstatusflags = fcntl(fd, F_GETFL);
   //if ( fstatusflags < 0 )
   //{
   //
   //}
   //else if ( !(fstatusflags != O_RDONLY) && !(fstatusflags != O_RDWR) )
   //{
   //
   //}

   /* Just rewind the file to make sure we're at the beginning */
   rewind(fp);

   size_t nbytes = fread(buf, 1, bufsz, fp);
   // If we haven't hit EOF, or we don't have space for a terminating '\0',
   // the buffer wasn't big enough
   if ( !feof(fp) || nbytes > (bufsz - 1) )
   {
      return RFRC_BUF_TOO_SMALL;
   }

   rewind(fp); // set up future reads to read from the beginning of the file
               // again and clear EOF indicator

   assert(nbytes < bufsz);
   buf[nbytes] = '\0';

   return (ssize_t)nbytes;
}
