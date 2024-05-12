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

// Session keys and shared secrets
dhKey myKey;
dhKey peerKey;
unsigned char sharedSecret[512];

static GtkTextBuffer *tbuf; /* transcript buffer */
static GtkTextBuffer *mbuf; /* message buffer */
static GtkTextView *tview;  /* view for transcript */
static GtkTextMark *mark;   /* used for scrolling to end of transcript, etc */

static pthread_t trecv; /* wait for incoming messagess and post to queue */
void *recvMsg(void *);  /* for trecv */

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
    unsigned char sessionKey[256];
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

    GtkTextIter mstart; /* start of message pointer */
    GtkTextIter mend;   /* end of message pointer */
    gtk_text_buffer_get_start_iter(mbuf, &mstart);
    gtk_text_buffer_get_end_iter(mbuf, &mend);
    char *message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);
    size_t len = g_utf8_strlen(message, -1);

    /* XXX we should probably do the actual network stuff in a different
     * thread and have it call this once the message is actually sent. */
    ssize_t nbytes;
    if ((nbytes = send(sockfd, message, len, 0)) == -1)
    {
        error("send failed");
    }

    tsappend(message, NULL, 1);
    free(message);

    /* clear message text and reset focus */
    gtk_text_buffer_delete(mbuf, &mstart, &mend);
    gtk_widget_grab_focus(w);
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
    size_t maxlen = 512;
    char msg[maxlen + 2]; /* might add \n and \0 */
    ssize_t nbytes;

    while (1)
    {
        if ((nbytes = recv(sockfd, msg, maxlen, 0)) == -1)
            error("recv failed");
        if (nbytes == 0)
        {
            /* XXX maybe show in a status message that the other
             * side has disconnected. */
            return 0;
        }
        char *m = malloc(maxlen + 2);
        memcpy(m, msg, nbytes);
        if (m[nbytes - 1] != '\n')
            m[nbytes++] = '\n';
        m[nbytes] = 0;
        g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
    }
    return 0;
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
    {
        perror("Failed to send public key");
    }

    free(pub_key_str);
}

void recv_dh_key(int sockfd, dhKey *key)
{
    char buffer[2048];
    int len = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (len < 0)
    {
        perror("Failed to receive public key");
        return;
    }
    buffer[len] = '\0';
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