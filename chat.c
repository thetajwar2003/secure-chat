#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include <limits.h> // For HOST_NAME_MAX

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

// Global variables for session keys and shared secrets
dhKey myKey;
dhKey peerKey;
unsigned char sharedSecret[512];

// Global variables for hmac and aes
unsigned char aes_key[32];	// AES key for encryption and decryption
unsigned char hmac_key[64]; // Key for HMAC

// Global variables for incoming/outgoing sequence numbers
unsigned long long send_sequence = 0;
unsigned long long recv_sequence = 0;

static GtkTextBuffer *tbuf; /* transcript buffer */
static GtkTextBuffer *mbuf; /* message buffer */
static GtkTextView *tview;	/* view for transcript */
static GtkTextMark *mark;	/* used for scrolling to end of transcript, etc */

static pthread_t trecv; /* wait for incoming messagess and post to queue */
void *recvMsg(void *);	/* for trecv */

#define max(a, b) \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	struct sockaddr_in cli_addr;
	socklen_t clilen;

	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");

	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);

	if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");

	fprintf(stderr, "listening on port %i...\n", port);
	listen(listensock, 1);

	sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");

	fprintf(stderr, "Server connection made, starting secure session...\n");

	// Generate DH key
	dhGenk(&myKey);
	// Send public key
	send_dh_key(sockfd, &myKey);
	// Receive client's public key
	recv_dh_key(sockfd, &peerKey);
	// Derive the shared secret
	unsigned char sessionKey[256]; // Adjust size as needed
	dhFinal(myKey.SK, myKey.PK, peerKey.PK, sessionKey, sizeof(sessionKey));

	// Load RSA keys
	RSA *rsa_private = load_rsa_private_key("server_private.pem");
	RSA *rsa_public = load_rsa_public_key("client_public.pem");

	// Perform mutual authentication
	send_challenge(sockfd);
	receive_challenge_and_respond(sockfd, rsa_private);
	verify_signature(sockfd, rsa_public);

	close(listensock);
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char *hostname, int port)
{
	struct sockaddr_in serv_addr;
	struct hostent *server;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	server = gethostbyname(hostname);

	if (sockfd < 0)
		error("ERROR opening socket");

	if (server == NULL)
	{
		fprintf(stderr, "ERROR, no such host\n");
		exit(0);
	}

	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
	serv_addr.sin_port = htons(port);

	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */

	fprintf(stderr, "Connected to %s, starting secure session...\n", hostname);

	// Generate DH key
	dhGenk(&myKey);
	// Send public key
	send_dh_key(sockfd, &myKey);
	// Receive server's public key
	recv_dh_key(sockfd, &peerKey);
	// Derive the shared secret
	unsigned char sessionKey[256]; // Adjust size as needed
	dhFinal(myKey.SK, myKey.PK, peerKey.PK, sessionKey, sizeof(sessionKey));

	// Load RSA keys
	RSA *rsa_private = load_rsa_private_key("client_private.pem");
	RSA *rsa_public = load_rsa_public_key("server_public.pem");

	// Perform mutual authentication
	receive_challenge_and_respond(sockfd, rsa_private);
	send_challenge(sockfd);
	verify_signature(sockfd, rsa_public);

	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd, 2);
	unsigned char dummy[64];
	ssize_t r;
	do
	{
		r = recv(sockfd, dummy, 64, 0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */

static const char *usage =
	"Usage: %s [OPTIONS]...\n"
	"Secure chat (CCNY computer security project).\n\n"
	"   -c, --connect HOST  Attempt a connection to HOST.\n"
	"   -l, --listen        Listen for new connections.\n"
	"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
	"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char *message, char **tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf, &t0);
	size_t len = g_utf8_strlen(message, -1);
	if (ensurenewline && message[len - 1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf, &t0, message, len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf, &t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0, len);
	if (tagnames)
	{
		char **tag = tagnames;
		while (*tag)
		{
			gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
			tag++;
		}
	}
	if (!ensurenewline)
		return;
	gtk_text_buffer_add_mark(tbuf, mark, &t1);
	gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
	gtk_text_buffer_delete_mark(tbuf, mark);
}

static void sendMessage(GtkWidget *w /* <-- msg entry widget */, gpointer /* data */)
{
	char *tags[2] = {"self", NULL};
	tsappend("me: ", tags, 0);

	GtkTextIter mstart, mend;
	gtk_text_buffer_get_start_iter(mbuf, &mstart);
	gtk_text_buffer_get_end_iter(mbuf, &mend);
	char *message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, FALSE);
	size_t len = strlen(message); // Get the length of the message

	// Encrypt message
	unsigned char iv[16];
	RAND_bytes(iv, sizeof(iv)); // Generate IV

	unsigned char ct[512];
	int ctlen = 0;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
		return;
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, iv) != 1)
	{
		fprintf(stderr, "Encryption initialization failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	if (EVP_EncryptUpdate(ctx, ct, &ctlen, (unsigned char *)message, len) != 1)
	{
		fprintf(stderr, "Encryption failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	int out_len;
	if (EVP_EncryptFinal_ex(ctx, ct + ctlen, &out_len) != 1)
	{
		fprintf(stderr, "Encrypt Final failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}
	ctlen += out_len;

	EVP_CIPHER_CTX_free(ctx);

	// Compute HMAC
	unsigned char mac[64]; // Assuming SHA512
	HMAC(EVP_sha512(), hmac_key, sizeof(hmac_key), ct, ctlen, mac, NULL);

	// Send IV, the encrypted message, HMAC, and sequence
	size_t total_len = sizeof(iv) + ctlen + sizeof(mac) + sizeof(send_sequence);
	unsigned char *packet = malloc(total_len);
	if (!packet)
	{
		perror("Failed to allocate packet memory");
		return;
	}

	// Copy sequence number at the beginning of the packet
	memcpy(packet, &send_sequence, sizeof(send_sequence));
	memcpy(packet + sizeof(send_sequence), iv, sizeof(iv));
	memcpy(packet + sizeof(send_sequence) + sizeof(iv), ct, ctlen);
	memcpy(packet + sizeof(send_sequence) + sizeof(iv) + ctlen, mac, sizeof(mac));

	ssize_t nbytes = send(sockfd, packet, total_len, 0);
	if (nbytes == -1)
	{
		perror("send failed");
	}

	free(packet);
	tsappend(message, NULL, 1);
	free(message);

	// Clear message text and reset focus
	gtk_text_buffer_delete(mbuf, &mstart, &mend);
	gtk_widget_grab_focus(w);

	// Increment sequence number after sending
	send_sequence++;
}

static gboolean shownewmessage(gpointer msg)
{
	char *tags[2] = {"friend", NULL};
	char *friendname = "mr. friend: ";
	tsappend(friendname, tags, 0);
	char *message = (char *)msg;
	tsappend(message, NULL, 1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0)
	{
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect", required_argument, 0, 'c'},
		{"listen", no_argument, 0, 'l'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX + 1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1)
	{
		switch (c)
		{
		case 'c':
			if (strnlen(optarg, HOST_NAME_MAX))
				strncpy(hostname, optarg, HOST_NAME_MAX);
			break;
		case 'l':
			isclient = 0;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			printf(usage, argv[0]);
			return 0;
		case '?':
			printf(usage, argv[0]);
			return 1;
		}
	}

	// initialize hmac and aes
	static const unsigned char aes_key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

	unsigned char static_hmac_key[64] = {
		0xbe, 0x41, 0x62, 0x1e, 0xa9, 0xf9, 0xef, 0x7b,
		0x6a, 0x2b, 0xab, 0x5a, 0xe3, 0xe6, 0x2d, 0xa2,
		0xf9, 0xcc, 0xff, 0x3c, 0x76, 0x20, 0xce, 0x63,
		0x35, 0xff, 0x9c, 0x0e, 0xed, 0x79, 0xa4, 0xba,
		0xbe, 0x41, 0x62, 0x1e, 0xa9, 0xf9, 0xef, 0x7b,
		0x6a, 0x2b, 0xab, 0x5a, 0xe3, 0xe6, 0x2d, 0xa2,
		0xf9, 0xcc, 0xff, 0x3c, 0x76, 0x20, 0xce, 0x63,
		0x35, 0xff, 0x9c, 0x0e, 0xed, 0x79, 0xa4, 0xba};
	memcpy(hmac_key, static_hmac_key, sizeof(hmac_key));

	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient)
	{
		// generate client rsa keys
		generate_rsa_keys("client_private.pem", "client_public.pem");
		printf("Client RSA keys generated successfully.\n");

		initClientNet(hostname, port);
	}
	else
	{
		// generate server rsa keys
		generate_rsa_keys("server_private.pem", "server_public.pem");
		printf("Server RSA keys generated successfully.\n");

		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder *builder;
	GObject *window;
	GObject *button;
	GObject *transcript;
	GObject *message;
	GError *error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder, "layout.ui", &error) == 0)
	{
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark = gtk_text_mark_new(NULL, TRUE);
	window = gtk_builder_get_object(builder, "window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider *css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css, "colors.css", NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
											  GTK_STYLE_PROVIDER(css),
											  GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf, "status", "foreground", "#657b83", "font", "italic", NULL);
	gtk_text_buffer_create_tag(tbuf, "friend", "foreground", "#6c71c4", "font", "bold", NULL);
	gtk_text_buffer_create_tag(tbuf, "self", "foreground", "#268bd2", "font", "bold", NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv, 0, recvMsg, 0))
	{
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void *recvMsg(void *)
{
	size_t maxlen = 512 + 64 + 16 + sizeof(unsigned long long); // Adjust based on expected packet size
	unsigned char packet[maxlen];
	ssize_t nbytes;

	while (1)
	{
		nbytes = recv(sockfd, packet, sizeof(packet), 0);
		if (nbytes == -1)
		{
			perror("recv failed");
			continue;
		}
		if (nbytes == 0)
		{
			printf("Connection closed by peer\n");
			break;
		}

		// Extract sequence number from the packet
		unsigned long long packet_sequence;
		memcpy(&packet_sequence, packet, sizeof(packet_sequence));
		unsigned char *iv = packet + sizeof(unsigned long long);

		// Correctly calculate the start of the ciphertext and its length
		unsigned char *ciphertext = packet + sizeof(unsigned long long) + 16;
		int ciphertext_len = nbytes - 16 - 64 - sizeof(unsigned long long); // Subtracted sizes of IV, HMAC, and sequence number
		unsigned char *received_mac = packet + nbytes - 64;

		// Verify HMAC
		unsigned char mac[64];
		HMAC(EVP_sha512(), hmac_key, sizeof(hmac_key), ciphertext, ciphertext_len, mac, NULL);
		if (memcmp(mac, received_mac, 64) != 0)
		{
			fprintf(stderr, "HMAC verification failed\n");
			continue;
		}

		// Decrypt message
		unsigned char plaintext[1024];
		int plaintext_len = 0;

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		if (!ctx)
		{
			fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
			continue;
		}

		if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, iv))
		{
			fprintf(stderr, "Decrypt Init failed: ");
			ERR_print_errors_fp(stderr);
			EVP_CIPHER_CTX_free(ctx);
			continue;
		}

		if (!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len))
		{
			fprintf(stderr, "Decrypt Update failed\n");
			EVP_CIPHER_CTX_free(ctx);
			continue;
		}

		int final_len = 0;
		if (!EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &final_len))
		{
			fprintf(stderr, "Decrypt Final failed: ");
			ERR_print_errors_fp(stderr);
			EVP_CIPHER_CTX_free(ctx);
			continue;
		}
		plaintext_len += final_len;
		plaintext[plaintext_len] = '\0';

		EVP_CIPHER_CTX_free(ctx);

		printf("Decrypted message length: %d\nDecrypted message content: '%s'\n", plaintext_len, plaintext);

		// Pass the decrypted message
		char *msg_to_show = strdup(plaintext);
		if (msg_to_show)
		{
			g_main_context_invoke(NULL, shownewmessage, msg_to_show);
		}
		else
		{
			fprintf(stderr, "Failed to allocate memory for decrypted message\n");
		}

		// Increment expected sequence number after successful processing
		recv_sequence++;
	}

	return NULL;
}

// ephemeral keys
void send_dh_key(int sockfd, dhKey *key)
{
	// Convert mpz_t public key to string
	char *pub_key_str = mpz_get_str(NULL, 10, key->PK);
	if (pub_key_str == NULL)
	{
		fprintf(stderr, "Failed to serialize public key\n");
		return;
	}

	// Send the public key string over the socket
	if (send(sockfd, pub_key_str, strlen(pub_key_str) + 1, 0) == -1)
	{ // +1 to include null terminator
		perror("Failed to send public key");
	}

	// Free the allocated string buffer
	free(pub_key_str);
}

void recv_dh_key(int sockfd, dhKey *key)
{
	char buffer[2048]; // Buffer size to adjust based on expected key size
	int len = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
	if (len < 0)
	{
		perror("Failed to receive public key");
		return;
	}
	buffer[len] = '\0'; // Null-terminate the received string

	// Initialize and set the peer's public key from the received string
	mpz_init(key->PK);
	if (mpz_set_str(key->PK, buffer, 10) != 0)
	{ // Base 10 for conversion
		fprintf(stderr, "Failed to deserialize public key\n");
	}
}

// encryption
void send_challenge(int socket_fd)
{
	unsigned char challenge[256]; // Proper size for RSA operations
	if (!RAND_bytes(challenge, sizeof(challenge)))
	{
		fprintf(stderr, "Failed to generate random bytes for challenge\n");
		return;
	}

	// Send challenge securely (consider encrypting this if necessary)
	if (send(socket_fd, challenge, sizeof(challenge), 0) < 0)
	{
		perror("Sending challenge failed");
		return;
	}

	// Save the challenge for later verification
	memcpy(sharedSecret, challenge, sizeof(challenge));
}

void receive_challenge_and_respond(int socket_fd, RSA *private_key)
{
	if (private_key == NULL)
	{
		fprintf(stderr, "Invalid private RSA key\n");
		return;
	}

	unsigned char challenge[256];
	if (recv(socket_fd, challenge, sizeof(challenge), 0) < 0)
	{
		perror("Receiving challenge failed");
		return;
	}

	// Save the challenge right after receiving for consistency in verification
	memcpy(sharedSecret, challenge, sizeof(challenge));

	// Hash the challenge before signing
	unsigned char hash[SHA256_DIGEST_LENGTH];
	if (!SHA256(challenge, sizeof(challenge), hash))
	{
		fprintf(stderr, "Failed to compute hash of challenge\n");
		return;
	}

	unsigned char *signature = malloc(RSA_size(private_key));
	unsigned int sig_len;

	if (!RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, private_key))
	{
		fprintf(stderr, "Failed to sign challenge: %s\n", ERR_error_string(ERR_get_error(), NULL));
		free(signature);
		return;
	}

	if (send(socket_fd, signature, sig_len, 0) < 0)
	{
		perror("Sending signature failed");
		free(signature);
		return;
	}

	free(signature);
}

void verify_signature(int socket_fd, RSA *public_key)
{
	unsigned char signature[RSA_size(public_key)];
	unsigned int sig_len = recv(socket_fd, signature, sizeof(signature), 0);
	if (sig_len < 0)
	{
		perror("Receiving signature failed");
		return;
	}

	unsigned char hash[SHA256_DIGEST_LENGTH];
	if (!SHA256(sharedSecret, sizeof(sharedSecret), hash))
	{
		fprintf(stderr, "Failed to compute hash of challenge for verification\n");
		return;
	}

	if (!RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, public_key))
	{
		fprintf(stderr, "Authentication failed\n");
	}
	else
	{
		fprintf(stderr, "Authentication successful\n");
	}
}