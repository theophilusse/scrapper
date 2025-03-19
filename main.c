#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define ALLOC(x) malloc(x)
#define FREE(x) free(x)
#define DEBUG printf("%s : %d\n", __func__, __LINE__);

///#define _WIN32
// Ne pas oublier -lws2_32 sur Windows

#define SSL_ENABLED

#ifdef _WIN32
// Windows-specific includes
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <sys/socket.h>
#endif
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h> // read(), write(), close()
#define SA struct sockaddr

#define PROTOCOL_HTTP 0
#define PROTOCOL_SOCKS5 1
#define PORT_MIN 1024
#define PORT_MAX 65535
#define TIMEOUT 5 // Timeout en secondes
#define THREAD_COUNT 400 /// More than 1 bug

#define STRING_SIZE 128

typedef unsigned int    uint;
typedef unsigned char   uchar;

int                 is_printable(char c)
{
    if (c >= ' ' && c <= '~')
        return (1);
    return (0);
}

int                 is_numeric(char c)
{
    if (c >= '0' && c <= '9')
        return (1);
    return (0);
}

int                 is_uppercase(char c)
{
    if (c >= 'A' && c <= 'Z')
        return (1);
    return (0);
}

int                 is_lowercase(char c)
{
    if (c >= 'a' && c <= 'z')
        return (1);
    return (0);
}

int                 is_alpha(char c)
{
    if (is_uppercase(c) || is_lowercase(c))
        return (1);
    return (0);
}

int                 is_alphanum(char c)
{
    if (is_numeric(c) || is_alpha(c))
        return (1);
    return (0);
}

#ifndef _WIN32
char* itoa(int value, char* str, int base) {
    int i = 0;
    int isNegative = 0;

    // Handle 0 explicitly
    if (value == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }

    // Handle negative numbers for base 10
    if (value < 0 && base == 10) {
        isNegative = 1;
        value = -value;
    }

    // Convert the number to the given base
    while (value != 0) {
        int rem = value % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        value = value / base;
    }

    // Append the negative sign for negative numbers
    if (isNegative) {
        str[i++] = '-';
    }

    str[i] = '\0'; // Null-terminate the string

    // Reverse the string
    for (int j = 0; j < i / 2; j++) {
        char temp = str[j];
        str[j] = str[i - j - 1];
        str[i - j - 1] = temp;
    }

    return str;
}
#endif
///////

typedef struct s_buf
{
    uint blocksize;
    uint size;
    void *buf;
}               t_buf;

typedef struct s_buf_param
{
    char                name[STRING_SIZE];
    struct s_buf        data;
}               t_buf_param;

typedef struct s_html_node
{
    struct s_html_node *parent;
    char                tag[STRING_SIZE];
    struct s_buf        child;
    struct s_buf        param;
    char                *text;
    int                 is_inline;
}               t_html_node;

struct s_buf    buffer_new(uint blocksize, uint size)
{
    struct s_buf buf;

    buf.blocksize = blocksize;
    buf.size = size;
    if (size > 0)
    {
        buf.buf = ALLOC(blocksize * size);
        memset(buf.buf, 0, blocksize * size);
    }
    else
        buf.buf = NULL;
    return (buf);
}

int             buffer_realloc(t_buf *buf, uint size)
{
    void        *data;

    if (!buf || !(data = ALLOC(size * buf->blocksize)))
        return (1);
    if (size < buf->size && buf->buf)
    {
        memcpy(data, buf->buf, buf->blocksize * size);
        buf->size = size;
        FREE(buf->buf);
        buf->buf = data;
        return (0);
    }
    memset(data, 0, size * buf->blocksize);
    if (buf->buf)
    {
        memcpy(data, buf->buf, buf->blocksize * buf->size);
        FREE(buf->buf);
    }
    buf->size = size;
    buf->buf = data;
    return (0);
}

void            *buffer_set_index(t_buf *buf, uint index, void *data)
{
    uint        offset;

    if (index >= buf->size)
        return (NULL);
    offset = buf->blocksize * index;
    memcpy(buf->buf + offset, data, buf->blocksize);
    return (buf->buf + offset);
}

void            *buffer_get_index(t_buf *buf, uint index)
{
    if (index >= buf->size)
        return (NULL);
    return (buf->buf + index * buf->blocksize);
}

void            buffer_delete_index(t_buf *buf, uint index)
{
    void        *cpy;

    if (!buf || index < 0 || index >= buf->size)
        return ;
    if (buf->size == 1)
    {
        buf->size = 0;
        FREE(buf->buf);
        buf->buf = NULL;
        return ;
    }
    if (!(cpy = ALLOC(buf->blocksize * (buf->size - 1))))
        return ;
    if (index > 0)
        memcpy(cpy, buf->buf, buf->blocksize * index);
    if (index + 1 < buf->size)
        memcpy(cpy + buf->blocksize * index, buf->buf + buf->blocksize * (index + 1), buf->blocksize * (buf->size - (index + 1)));
    FREE(buf->buf);
    buf->buf = cpy;
    buf->size--;
}

static void        print_tab(uint tab)
{
    while (tab--)
        printf("\t");
}

void        buffer_display_param(t_buf_param *param, uint tab)
{
    if (!param)
        return ;
    print_tab(tab);
    printf("Param [%s]=[%s]\n", param->name, (char *)param->data.buf);
}

//////////////////////////////////////////////////////////// STRING

uint        string_count_char(char *str, char c, uint max)
{
    uint        count;
    uint        i;

    if (!str)
        return (0);
    count = 0;
    i = -1;
    while (str[++i] && i < max)
        if (str[i] == c)
            count++;
    return (count);
}

char            *string_remove_char(char *str, char c)
{
    uint        size;
    char        *string;
    char        *ret;

    if (!str)
        return (NULL);
    size = strlen(str) - string_count_char(str, c, strlen(str)); // Verify size
    if (!(string = ALLOC(size + 1)))
        return (NULL);
    ret = string;
    memset(string, 0, size + 1);
    while (*str) // && count++ < size)
    {
        if (*str != c)
        {
            *string = *str;
            string++;
        }
        str++;
    }
    return (ret);
}

//////////////////////////////////////////////////////////// HTML

void        html_display_node(t_html_node *node, uint tab)
{
    int         i;

    if (!node)
        return ;
    print_tab(tab);
    printf("------------------\n");
    print_tab(tab);
    printf("Node [%s] @ [%p]\n", node->tag, node);
    print_tab(tab);
    printf("Parent [%p]\n", node->parent);
    i = -1;
    while (++i < node->param.size)
        buffer_display_param(buffer_get_index(&node->param, i), tab);
    if (node->text)
    {
        print_tab(tab);
        printf("Text [%s]\n", node->text);
    }
    i = -1;
    while (++i < node->child.size)
        html_display_node(buffer_get_index(&node->child, i), tab + 1);
}

void        html_display_node_max(t_html_node *node, uint tab, uint maxdepth)
{
    int         i;

    if (!node || maxdepth == 0)
        return ;
    print_tab(tab);
    printf("------------------\n");
    print_tab(tab);
    printf("Node [%s] @ [%p]\n", node->tag, node);
    print_tab(tab);
    printf("Parent [%p]\n", node->parent);
    i = -1;
    while (++i < node->param.size)
        buffer_display_param(buffer_get_index(&node->param, i), tab);
    if (node->text)
    {
        print_tab(tab);
        printf("Text [%s]\n", node->text);
    }
    i = -1;
    while (++i < node->child.size)
        html_display_node_max(buffer_get_index(&node->child, i), tab + 1, maxdepth - 1);
}

void debug_hexdump(char *data, uint length)
{
    uint        k;
    uint        j;
    uint        i;
    uint        counter;

    if (!data || length == 0)
        return ;
    counter = 0;
    while (counter < length)
    {
        k = 0;
        while (k < 4)
        {
            //printf("%x", ((char *)&i)[k]);
            if (((char *)&counter)[k] >= 16)
                printf("%x", ((unsigned char *)&counter)[k]);
            else
                printf("0%x", ((unsigned char *)&counter)[k]);
            k++;
        }
        printf(" ");
        j = 0;
        while (j < 16 && j + counter < length)
        {
            k = -1;
            while (++k < 2 && counter + j + k < length)
                printf("%02x", (unsigned char)data[counter + j + k]);
            j += k;
            printf(" ");
        }
        counter += j;
        printf("\n");
    }
}

void debug_string(char *str, uint count)
{
    printf("DEBUG STRING [");
    if (!str)
    {
        printf("(null)]\n");
        return ;
    }
    while (count-- && *str)
        printf("%c", *(str++));
    printf("]\n");
}

void    debug_display_int(t_buf *buf) ////////////////////////////
{
    int i;
    i = -1;
    while (++i < buf->size)
    {
        int *j;
        j = buffer_get_index(buf, i);
        printf("BUF[%d] -> %d\n", i, *j);
    }
}

void            buffer_display_param_list(t_buf *list)
{
    t_buf_param     *param;
    int             i;

    if (!list)
        return ;
    i = -1;
    while (++i < list->size)
    {
        printf("-----------------\n");
        param = *((t_buf_param **)buffer_get_index(list, i));
        printf("Param @ %p\n", param);
        buffer_display_param(param, 0);
    }
}

void    debug_display_ptr(t_buf *buf) ////////////////////////////
{
    int i;
    i = -1;
    while (++i < buf->size)
    {
        int **j;
        j = buffer_get_index(buf, i);
        printf("BUF[%d] -> %p\n", i, *j);
    }
}

void                *buffer_free(t_buf *buf)
{
    if (!buf)
        return (NULL);
    buf->size = 0;
    if (buf->buf)
        FREE(buf->buf);
    buf->buf = NULL;
    return (NULL);
}

void                *buffer_free_param(t_buf_param *param)
{
    if (param)
    {
        buffer_free(&param->data);
    }
    return (NULL);
}

void                *html_free_node_noroot(t_html_node *node)
{
    uint            i;

    if (!node)
        return (NULL);
    DEBUG //
    i = -1;
    while (++i < node->param.size)
        buffer_free_param((t_buf_param *)buffer_get_index(&node->param, i));
    DEBUG //
    i = -1;
    while (++i < node->child.size)
        html_free_node_noroot((t_html_node *)buffer_get_index(&node->child, i));
    DEBUG //
    if (node->text)
        FREE(node->text);
    DEBUG //
    if (node->parent)
    {
        html_display_node_max(node, 1, 2); //
        FREE(node);
    }
    DEBUG //
    return (NULL);
}

void                *html_free_node(t_html_node *node)
{
    uint            i;

    if (!node)
        return (NULL);
    i = -1;
    while (++i < node->param.size)
        buffer_free_param((t_buf_param *)buffer_get_index(&node->param, i));
    i = -1;
    while (++i < node->child.size)
        html_free_node((t_html_node *)buffer_get_index(&node->child, i));
    if (node->text)
        FREE(node->text);
    FREE(node);
    return (NULL);
}

int                 string_is_number(char *str)
{
    uint            dot;

    if (!str)
        return (0);
    if (*str == '-')
        if (!*(++str))
            return (0);
    dot = 0;
    while (*str)
    {
        if (!is_numeric(*str))
        {
            if (*str == '.')
            {
                if (++dot == 2)
                    return (0);
            }
            else
                return (0);
        }
        str++;
    }
    return (1);
}

char                *string_goto(char *src, char c)
{
    if (!src)
        return (NULL);
    while (*src && *src != c)
        src++;
    if (!*src)
        return (NULL);
    return (src);
}

char                *string_goto_nonnull(char *src, char c)
{
    if (!src)
        return (NULL);
    while (*src && *src != c)
        src++;
    return (src);
}

int                 string_char_in(char *src, char c)
{
    while (*src && *src != c)
        src++;
    if (*src == c)
        return (1);
    return (0);
}

char                *string_goto_multiple(char *src, char *c)
{
    if (!src)
        return (NULL);
    while (*src && !string_char_in(c, *src))
        src++;
    if (!*src)
        return (NULL);
    return (src);
}

char                *string_goto_numeric(char *src)
{
    while (*src && !is_numeric(*src))
        src++;
    if (!*src)
        return (NULL);
    return (src);
}

char                *string_goto_alphanum(char *src)
{
    while (*src && !is_alphanum(*src))
        src++;
    if (!*src)
        return (NULL);
    return (src);
}

char                *string_duplicate(char *str, uint length)
{
    char        *string;

    if (!str || length == 0 || !(string = ALLOC(length + 1)))
        return (NULL);
    memcpy(string, str, length);
    string[length] = '\0';
    return (string);
}

int                 is_blank(char c)
{
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        return (1);
    return (0);
}

char                *string_skipblank(char *str)
{
    if (!str)
        return (NULL);
    while (*str && is_blank(*str))
        str++;
    return (str);
}

char                *string_strip(char *str, char terminator)
{
    char        *begin;
    char        *end;

    if (!(begin = str) || *str == terminator)
        return (NULL);
    begin = string_skipblank(begin);
    if (*begin == terminator)
        return (NULL);
    end = begin + 1;
    while (*end && *end != terminator)
        end++;
    end--;
    while (end > begin && (*end == ' ' || *end == '\t' || *end == '\n'))
        end--;
    end++;
    return (string_duplicate(begin, end - begin));
}

char            *string_stradd_len(char *dst, char *src, uint length)
{
    char        *str;
    uint        dstlen;
    uint        srclen;

    if (!src)
        return (dst);
    srclen = length;
    if (!dst)
    {
        if (!(dst = ALLOC(srclen + 1)))
            return (NULL);
        memset(dst, 0, srclen + 1);
        strncpy(dst, src, srclen);
        return (dst);
    }
    dstlen = strlen(dst);
    if (!(str = ALLOC(dstlen + srclen + 1)))
        return (NULL);
    memset(str, 0, dstlen + srclen);
    strncpy(str, dst, dstlen + srclen);
    FREE(dst);
    return (strncat(str, src, dstlen + srclen));
}

char            *string_stradd(char *dst, char *src)
{
    char        *str;
    uint        dstlen;
    uint        srclen;

    if (!src)
        return (dst);
    srclen = strlen(src);
    if (!dst)
    {
        if (!(dst = ALLOC(srclen + 1)))
            return (NULL);
        memset(dst, 0, srclen + 1);
        strncpy(dst, src, srclen);
        return (dst);
    }
    dstlen = strlen(dst);
    if (!(str = ALLOC(dstlen + srclen + 1)))
        return (NULL);
    memset(str, 0, dstlen + srclen);
    strncpy(str, dst, dstlen + srclen);
    FREE(dst);
    return (strncat(str, src, dstlen + srclen));
}

char            *string_strdup(const char *str)
{
    uint        size;
    char        *dup;

    if (!str)
        return (NULL);
    size = strlen(str) + 1;
    if (!(dup = ALLOC(size)))
        return (NULL);
    dup[size - 1] = '\0';
    memcpy(dup, str, size);
    return (dup);
}

static char                 *html_new_string(char *trail, char **end)
{
    char              *string;
    char              *endofstring;
    char              delimiter;

    if (!trail)
        return (NULL);
    delimiter = *trail;
    if (delimiter != '"' && delimiter != '\'')
    {
        delimiter = ' ';
    }
    else
        trail++;
    endofstring = trail;
    while (*endofstring && *endofstring != delimiter)
    {
        endofstring++;
        if (*endofstring == delimiter && *(endofstring - 1) == '\\')
            endofstring++;
    }
    if (!(string = ALLOC(sizeof(char) * ((endofstring - trail) + 1))))
        return (NULL);
    string[endofstring - trail] = '\0';
    memcpy(string, trail, endofstring - trail);
    if (end)
        *end = endofstring;
    return (string);
}

t_buf_param         *buffer_new_param(char *trail, char **end)
{
    t_buf_param     *param;
    char             *endofstring;
    uint             size;
    char             *string;

    if (!trail || !(param = ALLOC(sizeof(struct s_buf_param))))
        return (NULL);
    memset(param, 0, sizeof(struct s_buf_param));
    if (!(endofstring = string_goto_multiple(trail, "= >")))
    {
        FREE(param);
        return (NULL);
    }
    if ((size = endofstring - trail) >= STRING_SIZE)
        size = STRING_SIZE;
    memcpy(param->name, trail, size);
    if (*endofstring != '=')
    {
        if (end)
            *end = endofstring - 1;
        return (param);
    }
    if (!(trail = string_skipblank(endofstring + 1)))
        return (param);
    if (!(string = html_new_string(trail, end)))
        return (param);
    param->data.blocksize = 1;
    param->data.size = strlen(string);
    param->data.buf = string;
    return (param);
}

int         buffer_push(t_buf *buf, void *data)
{
    uint            index;

    if (!data || !buf)
        return (1);
    index = buf->size;
    if (buffer_realloc(buf, buf->size + 1))
        return (1);
    buffer_set_index(buf, index, data);
    return (0);
}

int             buffer_concat(t_buf *dst, t_buf *src)
{
    uint        size;

    if (!dst || !src || dst->blocksize != src->blocksize)
        return (1);
    if (src->size == 0)
        return (0);
    size = dst->size;
    if (buffer_realloc(dst, dst->size + src->size))
        return (1);
    memcpy(dst->buf + (dst->blocksize * size), src->buf, src->blocksize * src->size); /// PLANTE
    return (0);
}

t_html_node         *html_new_node_string(char *string, t_html_node *parent)
{
    t_html_node     *node;

    if (!string || !(node = ALLOC(sizeof(struct s_html_node))))
        return (NULL);
    memset(node, 0, sizeof(struct s_html_node));
    node->parent = parent;
    node->param.blocksize = sizeof(t_buf_param);
    node->child.blocksize = sizeof(t_html_node);
    node->text = string;
    return (node);
}

int                 html_is_inline(char *parent_tag, char *tag, char *trail)
{
    if (*(trail - 2) == '/') // Test TODO
        return (1);
    if (strncasecmp(tag, "meta", strlen(tag)) == 0)
        return (1);
    if (strncasecmp(tag, "li", strlen(tag)) == 0)
        return (0);
    if (strncasecmp(tag, "ul", strlen(tag)) == 0)
        return (0);
    if (strncasecmp(tag, "ol", strlen(tag)) == 0)
        return (0);
    if (strncasecmp(tag, "link", strlen(tag)) == 0)
        return (1);
    if (strncasecmp(tag, "input", strlen(tag)) == 0)
        return (1);
    if (strncasecmp(tag, "br", strlen(tag)) == 0)
        return (1);
    if (strncasecmp(tag, "source", strlen(tag)) == 0)
        return (1);
    if (strncasecmp(tag, "html", strlen(tag)) == 0)
        return (0);
    while (*trail)
    {
        if (*trail == '<')
        {
            if (*(trail + 1) == '/')
            {
                trail += 2;
                if (strncasecmp(tag, trail, strlen(tag)) == 0)
                    return (0);
                if (parent_tag)
                {
                    if (strncasecmp(parent_tag, trail, strlen(tag)) == 0)
                        return (1);
                }
                //else if (strncasecmp("web", trail, strlen(tag)) == 0)
                //    return (1);
            }
        }
        trail++;
    }
    return (1);
}

static void                html_link_parent(t_html_node *node, t_html_node *parent)
{
    uint            i;

    node->parent = parent;
    i = -1;
    while (++i < node->child.size)
        html_link_parent((t_html_node *)buffer_get_index(&node->child, i), node);
}

char                *string_skip_string(char *trail)
{
    char        delimiter;

    if (!trail)
        return (NULL);
    delimiter = *trail;
    while (*trail && *trail != delimiter)
    {
        if (*trail == '\\' && trail[1] == delimiter)
            trail++;
        trail++;
    }
    return (trail);
}

char                *string_goto_endtag(char *tagname, char *trail)
{
    char            *end;
    char            *tmp;
    uint            traillen;
    uint            taglen;

    if (!trail || !tagname)
        return (NULL);
    traillen = strlen(trail);
    taglen = strlen(tagname);
    while (*trail)
    {
        if (traillen < 3 + taglen)
            return (trail);
        if (trail[0] == '<' && trail[1] == '/')
        {
            end = trail;
            trail += 2;
            traillen -= 2;
            if (strncasecmp(tagname, trail, taglen) == 0)
            {
                trail += taglen;
                traillen -= taglen;
                tmp = string_goto(trail, '>');
                traillen -= tmp - trail;
                trail = tmp;
                if (*trail == '>')
                    return (end);
            }
        }
        else if (trail[0] == '\'' || trail[0] == '"')
        {
            tmp = string_skip_string(trail);
            traillen -= tmp - trail;
            trail = tmp;
            if (!*trail)
                return (trail);
        }
        trail++;
        traillen--;
    }
    return (trail);
}

char                *string_goto_str(char *trail, char *string)
{
    if (!trail || !string)
        return (NULL);
    while (*trail && strncmp(trail, string, strlen(string)) != 0)
        trail++;
    if (!*trail)
        return (NULL);
    return (trail);
}

t_html_node         *html_root_node(t_html_node *node)
{
    while (node->parent)
        node = node->parent;
    return (node);
}

int                 html_is_special_tag(char *tagname)
{
    if (!tagname)
        return (0);
    if (strncasecmp(tagname, "style", STRING_SIZE) == 0 ||
        strncasecmp(tagname, "script", STRING_SIZE) == 0)
        return (1);
    return (0);
}

t_html_node         *html_new_node(char *tag, t_html_node *parent, char **end)
{
    t_html_node     *node;
    char            *trail;
    char            *endofstring;
    char            *nexttag;
    t_buf_param     *param;
    t_html_node     *inner_node;
    char            *string;

    if (!tag || !(node = ALLOC(sizeof(struct s_html_node))))
        return (NULL);
    memset(node, 0, sizeof(struct s_html_node));
    node->parent = parent;
    node->param.blocksize = sizeof(t_buf_param);
    node->child.blocksize = sizeof(t_html_node);
    string = NULL;
    nexttag = NULL;
    trail = tag;
    if (parent // Special case
        && html_is_special_tag(parent->tag))
    {
        endofstring = string_goto_endtag(parent->tag, trail);
        node->text = string_duplicate(trail, endofstring - trail);
        trail = string_goto(endofstring + strlen(parent->tag) + 2, '>');
        if (!trail)
            return (html_free_node(node));
        if (*trail)
            trail++;
        if (end)
            *end = trail;
        return (node);
    }
    while (*trail && *trail != '<') // Inner
    {
        if (!string && is_printable(*trail) && *trail != ' ' && *trail != '\t')
        {
            string = string_strip(trail, '<');
            if (!(trail = string_goto(trail, '<')))
                return (html_free_node(node));
            node->text = string;
            if (end)
                *end = trail;
            return (node);
        }
        trail++;
    }
    if (*(trail + 1) == '/') // End
    {
        if (parent)
            parent->text = string_strip(tag, '<');
        if (end)
            *end = string_goto(trail, '>') + 1;
        return (html_free_node(node));
    }
    else if (strncmp(trail, "<!--", strlen("<!--")) == 0) // Comment
    {
        strncpy(node->tag, "!--", 3);
        node->is_inline = 1;
        trail += strlen("<!--");
        if (!(trail = string_skipblank(trail)) ||
        !(endofstring = string_goto_str(trail, "-->")))
            return (html_free_node(node));
        endofstring--;
        while (is_blank(*endofstring))
            endofstring--;
        endofstring++;
        if (is_blank(*(endofstring - 1)))
            endofstring--;
        // bugshit
        if (endofstring > trail && endofstring - trail != 0)
            node->text = string_duplicate(trail, endofstring - trail);
        if (end)
            *end = string_goto_str(trail, "-->") + 4;
        return (node);
    }
    if (!(trail = string_goto_alphanum(trail)) ||
        !(endofstring = string_goto_multiple(trail, "\n\t />")))
        return (html_free_node(node));
    if (endofstring - trail >= STRING_SIZE)
        endofstring -= ((endofstring - trail) - STRING_SIZE) + 1;
    memcpy(node->tag, trail, endofstring - trail);
    trail = endofstring;
    while (*trail && *trail != '>') // New tag
    {
        if (is_alphanum(*trail))
        {
            if (!(param = buffer_new_param(trail, &trail))||
                buffer_push(&node->param, param)) // Test
            {
                buffer_free_param(param);
                return (html_free_node(node));
            }
            /*
            if (buffer_realloc(&node->param, node->param.size + 1))
                return (html_free_node(node));
            buffer_set_index(&node->param, node->param.size - 1, buffer_new_param(trail, &trail));
            */
        }
        trail++;
    }
    if (!trail)
        return (html_free_node(node)); /// TEST DEBUG
    trail++; // Inner
    if (node->parent)
        node->is_inline = html_is_inline(node->parent->tag, node->tag, trail);
    else
        node->is_inline = html_is_inline(NULL, node->tag, trail);
    if (!node->is_inline
        //&& strncasecmp(node->tag, "style", STRING_SIZE) != 0
        )
    {
        while ((inner_node = html_new_node(trail, node, &nexttag))) // Recursion
        {
            buffer_push(&node->child, inner_node);
            trail = nexttag;
            if (html_is_special_tag(node->tag))
                break;
        }
    }
    else
        nexttag = trail;
    if (end)
        *end = nexttag;
    if (!parent)
        html_link_parent(node, NULL);
    return (node);
}

t_buf_param        *html_get_param(t_html_node *node, uint index)
{
    if (!node)
        return (NULL);
    return (buffer_get_index(&node->param, index));
}

struct s_buf        html_get_param_name(t_html_node *node, char *name)
{
    struct s_buf        array;
    t_buf_param        *param;
    uint                i;
    uint                count;

    array.blocksize = sizeof(t_html_node *);
    array.size = 0;
    array.buf = NULL;
    if (!node || !name)
        return (array);
    i = -1;
    count = 0;
    while (++i < node->param.size)
    {
        param = html_get_param(node, i);
        if (strncasecmp(param->name, name, strlen(name)) == 0)
        {
            if (buffer_realloc(&array, ++count))
                return (array);
            buffer_set_index(&array, count - 1, &param);
        }
    }
    return (array);
}

struct s_buf    html_find_tag_param(t_html_node *node, char *tagname, char *paramname, char *id)
{
    struct s_buf    array;
    struct s_buf    merge;
    int             i;

    array.blocksize = sizeof(t_html_node *);
    array.size = 0;
    array.buf = NULL;
    if (!node || !tagname || !paramname || !id)
        return (array);

    struct s_buf    param;
    t_buf_param     *p;
    param = html_get_param_name(node, paramname);
    i = -1;
    if (strncmp(node->tag, tagname, strlen(node->tag)) == 0)
        while (++i < param.size)
        {
            p = *((t_buf_param **)buffer_get_index(&param, i));
            if (!p)
                continue;
            if (strncmp(p->data.buf, id, strlen(id)) == 0)
            {
                buffer_push(&array, &node);
                break;
            }
        }
    buffer_free(&param);
    i = -1;
    while (++i < node->child.size)
    {
        merge = html_find_tag_param((t_html_node *)buffer_get_index(&node->child, i), tagname, paramname, id);
        if (merge.size != 0 && buffer_concat(&array, &merge))
            return (array);
        buffer_free(&merge);
    }
    return (array);
}

struct s_buf    html_find_param(t_html_node *node, char *paramname, char *id)
{
    struct s_buf    array;
    struct s_buf    merge;
    int             i;

    array.blocksize = sizeof(t_html_node *);
    array.size = 0;
    array.buf = NULL;
    if (!node || !paramname || !id)
        return (array);

    struct s_buf    param;
    t_buf_param     *p;
    param = html_get_param_name(node, paramname);
    i = -1;
    while (++i < param.size)
    {
        p = *((t_buf_param **)buffer_get_index(&param, i));
        if (!p)
            continue;
        if (strncmp(p->data.buf, id, strlen(id)) == 0)
        {
            buffer_push(&array, &node);
            break;
        }
    }
    buffer_free(&param);
    i = -1;
    while (++i < node->child.size)
    {
        merge = html_find_param((t_html_node *)buffer_get_index(&node->child, i), paramname, id);
        if (merge.size != 0 && buffer_concat(&array, &merge))
            return (array);
        buffer_free(&merge);
    }
    return (array);
}

struct s_buf    html_find_class(t_html_node *node, char *name)
{
    struct s_buf    array;
    struct s_buf    merge;
    int             i;

    array.blocksize = sizeof(t_html_node *);
    array.size = 0;
    array.buf = NULL;
    if (!node || !name)
        return (array);

    struct s_buf    param;
    t_buf_param     *p;
    param = html_get_param_name(node, "class");
    i = -1;
    while (++i < param.size)
    {
        p = *((t_buf_param **)buffer_get_index(&param, i));
        if (!p)
            continue;
        if (strncmp(p->data.buf, name, strlen(name)) == 0)
        {
            buffer_push(&array, &node);
            break;
        }
    }
    buffer_free(&param);
    i = -1;
    while (++i < node->child.size)
    {
        merge = html_find_class((t_html_node *)buffer_get_index(&node->child, i), name);
        if (merge.size != 0 && buffer_concat(&array, &merge))
            return (array);
        buffer_free(&merge);
    }
    return (array);
}

struct s_buf    html_find_id(t_html_node *node, char *id)
{
    struct s_buf    array;
    struct s_buf    merge;
    int             i;

    array.blocksize = sizeof(t_html_node *);
    array.size = 0;
    array.buf = NULL;
    if (!node || !id)
        return (array);

    struct s_buf    param;
    t_buf_param     *p;
    param = html_get_param_name(node, "id");
    i = -1;
    while (++i < param.size)
    {
        p = *((t_buf_param **)buffer_get_index(&param, i));
        if (!p)
            continue;
        if (strncmp(p->data.buf, id, strlen(id)) == 0)
        {
            buffer_push(&array, &node);
            break;
        }
    }
    buffer_free(&param);
    i = -1;
    while (++i < node->child.size)
    {
        merge = html_find_id((t_html_node *)buffer_get_index(&node->child, i), id);
        if (merge.size != 0 && buffer_concat(&array, &merge))
            return (array);
        buffer_free(&merge);
    }
    return (array);
}

struct s_buf    html_find_tag(t_html_node *node, char *name)
{
    struct s_buf    array;
    struct s_buf    merge;
    int             i;

    array.blocksize = sizeof(t_html_node *);
    array.size = 0;
    array.buf = NULL;
    if (!node || !name)
        return (array);
    if (strncasecmp(node->tag, name, strlen(name)) == 0)
    {
        if (buffer_realloc(&array, 1))
            return (array);
        buffer_set_index(&array, 0, &node);
    }
    i = -1;
    while (++i < node->child.size)
    {
        merge = html_find_tag((t_html_node *)buffer_get_index(&node->child, i), name);
        if (merge.size != 0 && buffer_concat(&array, &merge))
            return (array);
        buffer_free(&merge);
    }
    return (array);
}

struct s_buf    html_find_tag_max(t_html_node *node, char *name, uint maxdepth)
{
    struct s_buf    array;
    struct s_buf    merge;
    int             i;

    array.blocksize = sizeof(t_html_node *);
    array.size = 0;
    array.buf = NULL;
    if (!node || !name)
        return (array);
    if (strncasecmp(node->tag, name, strlen(name)) == 0)
    {
        if (buffer_realloc(&array, 1))
            return (array);
        buffer_set_index(&array, 0, &node);
    }
    if (maxdepth > 0)
    {
        i = -1;
        while (++i < node->child.size)
        {
            merge = html_find_tag_max((t_html_node *)buffer_get_index(&node->child, i), name, maxdepth - 1);
            if (merge.size != 0 && buffer_concat(&array, &merge))
                return (array);
            buffer_free(&merge);
        }
    }
    return (array);
}

uint        html_count_tag(t_html_node *node, char *name)
{
    int             count;
    int             i;

    if (!node || !name)
        return (0);
    if (strncasecmp(node->tag, name, strlen(name)) == 0)
        count = 1;
    else
        count = 0;
    i = -1;
    while (++i < node->child.size)
        count += html_count_tag((t_html_node *)buffer_get_index(&node->child, i), name);
    return (count);
}

char            *buffer_param_get_var_buf_alt(t_buf *buf, char *varname)
{
    uint            i;
    struct s_buf    ret;
    t_buf_param     *param;

    if (!buf)
        return (NULL);
    i = -1;
    while (++i < buf->size)
    {
        param = (t_buf_param *)buffer_get_index(buf, i);
        if (strncasecmp(param->name, varname, strlen(varname)) == 0)
            return ((char *)param->data.buf);
    }
    return (NULL);
}

char            *buffer_param_get_var_buf(t_buf *buf, char *varname)
{
    uint            i;
    struct s_buf    ret;
    t_buf_param     *param;

    if (!buf)
        return (NULL);
    i = -1;
    while (++i < buf->size)
    {
        //param = *((t_buf_param **)buffer_get_index(buf, i)); // If Crash on Import see alt function below
        param = *((t_buf_param **)buffer_get_index(buf, i));
        if (strncasecmp(param->name, varname, strlen(varname)) == 0)
            return ((char *)param->data.buf);
    }
    return (NULL);
}

char            *buffer_param_get_var_buf_case(t_buf *buf, char *varname)
{
    uint            i;
    struct s_buf    ret;
    t_buf_param     *param;

    if (!buf)
        return (NULL);
    i = -1;
    while (++i < buf->size)
    {
        param = *((t_buf_param **)buffer_get_index(buf, i));
        //param = buffer_get_index(buf, i);
        if (strncmp(param->name, varname, strlen(varname)) == 0)
            return ((char *)param->data.buf);
    }
    return (NULL);
}

struct s_buf        html_find_node_param(t_html_node *node, char *name, char *data)
{
    struct s_buf    array;
    struct s_buf    merge;
    struct s_buf    list;
    t_buf_param    *param;
    int             i;

    array.blocksize = sizeof(t_html_node *);
    array.size = 0;
    array.buf = NULL;
    if (!node)
        return (array);
    if (data && !name)
    {
        i = -1;
        while (++i < node->param.size)
        {
            param = html_get_param(node, i);
            if (param->data.buf && strncasecmp((char *)param->data.buf, data, strlen(data)) == 0)
            {
                if (buffer_realloc(&array, 1))
                    return (array);
                buffer_set_index(&array, 0, &node);
            }
        }
    }
    else
    {
        list = html_get_param_name(node, name);
        if (list.size != 0)
        {
            if (!data)
            {
                if (buffer_realloc(&array, 1))
                    return (array);
                buffer_set_index(&array, 0, &node);
            }
            else
            {
                i = -1;
                while (++i < list.size)
                {
                    param = *((t_buf_param **)buffer_get_index(&list, i));
                    if (strncasecmp((char *)param->data.buf, data, strlen(data)) == 0)
                    {
                        if (buffer_realloc(&array, 1))
                            return (array);
                        buffer_set_index(&array, 0, &node);
                    }
                }
            }
        }
        buffer_free(&list);
    }
    i = -1;
    while (++i < node->child.size)
    {
        merge = html_find_node_param((t_html_node *)buffer_get_index(&node->child, i), name, data);
        if (merge.size != 0 && buffer_concat(&array, &merge))
            return (array);
        buffer_free(&merge);
    }
    return (array);
}

char                        string_getdelimiter(char *str)
{
    if (!str)
        return ('\'');
    while (*str)
    {
        if (*str == '\\')
        {
            str++;
            if (*str == '"')
                return ('"');
            else if (*str == '\'')
                return ('\'');
        }
        str++;
    }
    return ('"');
}

char                        *buffer_param_tostring_html(t_buf_param *param)
{
    char                *buffer;
    char                delimiter[2];

    delimiter[1] = '\0';
    delimiter[0] = string_getdelimiter(param->data.buf);
    buffer = string_stradd(NULL, param->name);
    buffer = string_stradd(buffer, "=");
    buffer = string_stradd(buffer, delimiter);
    buffer = string_stradd(buffer, param->data.buf);
    buffer = string_stradd(buffer, delimiter);
    return (buffer);
}

char                        *buffer_param_tostring_json(t_buf_param *param)
{
    char                *buffer;
    char                delimiter_left[2];
    char                delimiter_right[2];

    delimiter_left[1] = '\0';
    delimiter_left[0] = string_getdelimiter(param->name);
    buffer = string_stradd(NULL, delimiter_left);
    buffer = string_stradd(buffer, param->name);
    buffer = string_stradd(buffer, delimiter_left);
    buffer = string_stradd(buffer, ":");
    if (string_is_number(param->data.buf))
        buffer = string_stradd(buffer, param->data.buf);
    else
    {
        delimiter_right[1] = '\0';
        delimiter_right[0] = string_getdelimiter(param->data.buf);
        buffer = string_stradd(buffer, delimiter_right);
        buffer = string_stradd(buffer, param->data.buf);
        buffer = string_stradd(buffer, delimiter_right);
    }
    return (buffer);
}

char                        *html_get_comments(t_html_node *html)
{
    char        *child_text;
    char        *text;
    uint        i;


    if (!html ||
        strncasecmp(html->tag, "script", STRING_SIZE) == 0 ||
        strncasecmp(html->tag, "style", STRING_SIZE) == 0
        )
        return (NULL);
    text = NULL;
    if (html->text && strncasecmp(html->tag, "!--", STRING_SIZE) == 0)
    {
        text = string_stradd(text, html->text);
        text = string_stradd(text, "\n");
    }
    i = -1;
    while (++i < html->child.size)
    {
        child_text = html_get_comments(buffer_get_index(&html->child, i));
        if (child_text)
        {
            text = string_stradd(text, child_text);
            FREE(child_text);
        }
    }
    return (text);
}

char                        *html_get_texts(t_html_node *html)
{
    char        *child_text;
    char        *text;
    uint        i;


    if (!html ||
        strncasecmp(html->tag, "script", STRING_SIZE) == 0 ||
        strncasecmp(html->tag, "!--", STRING_SIZE) == 0 ||
        strncasecmp(html->tag, "style", STRING_SIZE) == 0
        )
        return (NULL);
    text = NULL;
    if (html->text)
    {
        text = string_stradd(text, html->text);
        text = string_stradd(text, "\n");
    }
    i = -1;
    while (++i < html->child.size)
    {
        child_text = html_get_texts(buffer_get_index(&html->child, i));
        if (child_text)
        {
            text = string_stradd(text, child_text);
            FREE(child_text);
        }
    }
    return (text);
}

char                        *html_get_text_tag(t_html_node *html, char *tagname)
{
    char        *child_text;
    char        *text;
    uint        i;


    if (!html || !tagname)
        return (NULL);
    text = NULL;
    if (strncasecmp(html->tag, tagname, STRING_SIZE) == 0)
    {
        child_text = html_get_texts(html);
        if (child_text)
        {
            text = string_stradd(text, child_text);
            FREE(child_text);
        }
    }
    i = -1;
    while (++i < html->child.size)
    {
        child_text = html_get_text_tag(buffer_get_index(&html->child, i), tagname);
        if (child_text)
        {
            text = string_stradd(text, child_text);
            FREE(child_text);
        }
    }
    return (text);
}

char                        *html_tostring(t_html_node *html)
{
    uint                i;
    t_buf_param         *param;
    t_html_node         *child;
    char                *buffer;
    char                *string;

    buffer = NULL;
    if (strlen(html->tag) > 0)
    {
        buffer = string_stradd(NULL, "<");
        buffer = string_stradd(buffer, html->tag);
        if (strncmp(html->tag, "!--", strlen(html->tag)) == 0)
        {
            buffer = string_stradd(buffer, " ");
            buffer = string_stradd(buffer, html->text);
            buffer = string_stradd(buffer, " -->");
        }
        else
        {
            if (html->param.size > 0)
                buffer = string_stradd(buffer, " ");
            i = -1;
            while (++i < html->param.size)
            {
                param = ((t_buf_param *)buffer_get_index(&html->param, i));
                string = buffer_param_tostring_html(param);
                buffer = string_stradd(buffer, string);
                FREE(string);
                if (i + 1 < html->param.size)
                    buffer = string_stradd(buffer, " ");
            }
            if (html->is_inline)
                buffer = string_stradd(buffer, "/");
            buffer = string_stradd(buffer, ">");
        }
    }
    if (html->text)
        buffer = string_stradd(buffer, html->text);
    i = -1;
    while (++i < html->child.size)
    {
        child = ((t_html_node *)buffer_get_index(&html->child, i));
        string = html_tostring(child);
        buffer = string_stradd(buffer, string);
    }
    if (strlen(html->tag) > 0 && !html->is_inline)
    {
        buffer = string_stradd(buffer, "</");
        buffer = string_stradd(buffer, html->tag);
        buffer = string_stradd(buffer, ">");
    }
    return (buffer);
}

struct s_html_node          html_parse(char *html)
{
    struct s_html_node     root;
    t_html_node            *node;
    uint                    count;

    memset(root.tag, 0, STRING_SIZE);
    root.parent = NULL;
    root.child = buffer_new(sizeof(t_html_node), 0);
    root.param = buffer_new(0, 0);
    root.text = NULL;
    count = 0;
    while ((node = html_new_node(html, NULL, &html)))
    {
        node->parent = &root;
        if (buffer_push(&root.child, node))
        {
            html_free_node(node);
            return (root);
        }
    }
    return (root);
}

//////////////////////////////////////////////////////////// URL

char     *url_get_proto(char *url)
{
    char        *proto;
    char        *endofstring;
    uint        size;

    if (!url)
        return (NULL);
    endofstring = url;
    while (*endofstring && *endofstring != ':')
        endofstring++;
    if (!*endofstring)
        return (NULL);
    size = endofstring - url;
    if (!(proto = ALLOC(size + 1)))
        return (NULL);
    memset(proto, 0, size + 1);
    return (strncpy(proto, url, size));
}

char     *url_get_host(char *url)
{
    char        *host;
    char        *endofstring;
    uint        size;

    if (!url)
        return (NULL);
    while (*url && *url != ':')
        url++;
    if (!*url)
        return (NULL);
    url++;
    endofstring = url;
    while (*endofstring && *endofstring == '/')
        endofstring++;
    if (!*endofstring || endofstring - url != 2 || !(url = endofstring))
        return (NULL);
    endofstring = url;
    while (*endofstring && *endofstring != '/' && *endofstring != ':')
        endofstring++;
    if (*endofstring)
    {
        char *ptr;
        ptr = endofstring;
        if (*ptr == ':')
        {
            ptr++;
            while (*ptr && *ptr != '/' && *ptr != ':')
                ptr++;
            if (*ptr == ':')
            {
                endofstring = ptr;
                while (*endofstring && *endofstring != '/')
                    endofstring++;
                if (!*endofstring)
                    return (NULL);
            }
        }
    }
    size = endofstring - url;
    if (!(host = ALLOC(size + 1)))
        return (NULL);
    memset(host, 0, size + 1);
    return (strncpy(host, url, size));
}

char        *url_get_domain(char *url)
{
    // Vérifier si l'URL est NULL
    if (url == NULL) {
        return NULL;
    }

    // Trouver le début du domaine
    char* start = strstr(url, "://");
    if (start) {
        start += 3; // Passer "://"
    } else {
        start = url; // Pas de schéma, commencer au début
    }

    // Trouver la fin du domaine
    const char* end = strchr(start, '/');
    if (end == NULL) {
        end = start + strlen(start); // Pas de chemin, aller jusqu'à la fin
    }

    // Calculer la longueur du domaine
    size_t domain_length = end - start;

    // Allouer de la mémoire pour le domaine
    char* domain = (char*)ALLOC(domain_length + 1);
    if (domain == NULL) {
        return NULL; // Échec de l'allocation
    }

    // Copier le domaine dans la nouvelle chaîne
    strncpy(domain, start, domain_length);
    domain[domain_length] = '\0'; // Terminer la chaîne

    return (domain);
}

int         url_get_port_proto(char *proto)
{
    if (!proto)
        return (-1);
    if (strncasecmp(proto, "http\0", strlen("http") + 1) == 0)
        return (80);
    if (strncasecmp(proto, "https\0", strlen("https") + 1) == 0)
        return (443);
    if (strncasecmp(proto, "ftp\0", strlen("ftp") + 1) == 0)
        return (21);
    if (strncasecmp(proto, "sftp\0", strlen("sftp") + 1) == 0)
        return (22);
    if (strncasecmp(proto, "ssh\0", strlen("ssh") + 1) == 0)
        return (22);
    return (-1);
}

int                             url_is_ipv6(char *host)
{
    struct sockaddr_in6     sa; // Structure pour stocker l'adresse IPv6
    char                    *hostname;

    if (!(hostname = url_get_host(host)) && !(hostname = string_strdup(host)))
        return (0);
    // Utiliser inet_pton pour convertir l'adresse IP en format binaire
    if (inet_pton(AF_INET6, hostname, &(sa.sin6_addr)) == 1)
    {
        FREE(hostname);
        return (1);
    }
    FREE(hostname);
    return (0);
}

int                             url_is_ipv4(char *host)
{
    int         count;
    int         i;
    char        *hostname;

    if (!(hostname = url_get_host(host)) && !(hostname = string_strdup(host)))
        return (0);
    host = hostname;
    count = 0;
    i = -1;
    while (*host && ++i < 27)
    {
        if (!is_numeric(*host) && *host != '.')
        {
            FREE(hostname);
            return (0);
        }
        if (*host == '.' && ((count += 1) >= 4 || *(host - 1) == '.'))
        {
            FREE(hostname);
            return (0);
        }
        host++;
    }
    FREE(hostname);
    if (count != 3)
        return (0);
    return (1);
}

////////////////////////////////////////////////////////////

typedef struct s_net_connection
{
    char        connected;
    char        ip[STRING_SIZE];
    int         port;
    char        *onion;
    int         protocol;
    #ifdef _WIN32
    WSADATA wsaData;
    SOCKET sock;
    //struct sockaddr_in server;
    #else
    int sock, connfd;
    struct sockaddr_in server, cli;
    struct sockaddr_in6 server_6;
    #endif
    char        *hostname;
    int ssl_enabled;
    #ifdef SSL_ENABLED
    SSL_CTX *ctx;
    SSL *ssl;
    #endif
}               t_net_connection;

#ifdef SSL_ENABLED
void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (1)
    {
        method = SSLv23_client_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) {
            ERR_print_errors_fp(stderr);
            return (NULL);
        }
        return (ctx);
    }
    else
    {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            //ERR_print_errors_fp(stderr);
            return (NULL);
        }
        return (ctx);
    }
}

void configure_context(SSL_CTX *ctx)
{
    // Set the default verification paths
    ///SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
    // Set minimum protocol version
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
    {
        ERR_print_errors_fp(stdin);
    }
    if (SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"))
    {
        ERR_print_errors_fp(stdin);
    }
}
#endif

struct s_net_connection     net_new_onion_connection(char *host, int port, int ssl)
{
    struct s_net_connection     con;

    ///printf("Connecting to [%s] Port: %d\n", host, port);
    memset(&con, 0, sizeof(struct s_net_connection));
    if (!host || port < 0)
        return (con);
    con.port = port;
    con.protocol = PROTOCOL_SOCKS5;
    strncpy(con.ip, "127.0.0.1", 16);
    #ifdef _WIN32
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &con.wsaData) != 0)
        return (con);
    #ifdef SSL_ENABLED
    // Init OpenSSL
    if (ssl)
    {
        con.ssl_enabled = 1;
    }
    #endif

    // Créer un socket
    con.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (con.sock == INVALID_SOCKET)
    {
        WSACleanup();
        return (con);
    }

    // Set up the server address structure
    con.server.sin_family = AF_INET;
    con.server.sin_port = htons(9050); // Port number
    con.server.sin_addr.s_addr = inet_addr("127.0.0.1"); // Ip
    #else
    // socket create and verification
    con.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (con.sock == -1)
        return (con);
    #ifdef SSL_ENABLED
    // Init OpenSSL
    if (ssl)
    {
        con.ssl_enabled = 1;
    }
    #endif
    // assign IP, PORT
    con.server.sin_family = AF_INET;
    con.server.sin_addr.s_addr = inet_addr("127.0.0.1");
    con.server.sin_port = htons(9050);
    #endif
    con.onion = string_strdup(host);
    return (con);
}

struct s_net_connection     net_new_connection(char *ip, char *hostname, int port, int ssl)
{
    struct s_net_connection     con;

    ///printf("Connecting to [%s] Port: %d\n", ip, port);
    memset(&con, 0, sizeof(struct s_net_connection));
    con.sock = -1;
    if (!ip || port < 0)
        return (con);
    if (hostname)
        con.hostname = string_strdup(hostname);
    con.port = port;
    strncpy(con.ip, ip, strlen(ip));
    #ifdef _WIN32
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &con.wsaData) != 0)
    {
        printf("WSAStartup failed.\n");
        return (con);
    }
    #endif
    // socket create and verification
    if (url_is_ipv6(ip))
    {
        con.sock = socket(AF_INET6, SOCK_STREAM, 0);
    }
    else if (url_is_ipv4(ip))
    {
        con.sock = socket(AF_INET, SOCK_STREAM, 0);
    }
    ///printf("Socket [%d]\n", con.sock); //
    if (con.sock == -1)
    {
        printf("Invalid socket.\n");
        #ifdef _WIN32
        WSACleanup();
        #endif
        return (con);
    }
    #ifdef SSL_ENABLED
    // Init OpenSSL
    if (ssl)
    {
        con.ssl_enabled = 1;
    }
    #endif
    // assign IP, PORT
    if (url_is_ipv4(ip))
    {
        con.server.sin_family = AF_INET;
        con.server.sin_addr.s_addr = inet_addr(ip);
        con.server.sin_port = htons(port);
    }
    else
    {
        con.server_6.sin6_family = AF_INET6;
        con.server_6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &con.server_6.sin6_addr) <= 0)
        {
            printf("Erreur lors de la conversion de l'adresse IP\n");
            close(con.sock);
            return (con);
        }
    }
    // Définir le timeout pour la réception
    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(con.sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(con.sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    // Définir le TTL
    int ttl = 16;
    if (setsockopt(con.sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt failed");
        close(con.sock);
        con.sock = -1;
        return (con);
    }
    return (con);
}

/// Socks5

#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_RESERVED 0x00
#define SOCKS5_ATYP_DOMAIN 0x03

void            net_socks5_display_reply(char rep)
{
    switch (rep)
    {
        /*
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
        */
        case 0:
            printf("Succeeded\n");
            break;
        case 1:
            printf("general SOCKS server failure\n");
            break;
        case 2:
            printf("connection not allowed by ruleset\n");
            break;
        case 3:
            printf("Network unreachable\n");
            break;
        case 4:
            printf("Host unreachable\n");
            break;
        case 5:
            printf("Connection refused\n");
            break;
        case 6:
            printf("TTL expired\n");
            break;
        case 7:
            printf("Command not supported\n");
            break;
        case 8:
            printf("Address type not supported\n");
            break;
        default:
            printf("Unknown\n");
    }
}

int         net_socks5_connect_host(t_net_connection *con, char *host)
{
    unsigned char   buf[256];
    int             len;

    if (!con || !host)
        return (1);

    ///printf("Sock5 Authentication\n");
    // Authentification (pas d'authentification)
    buf[0] = SOCKS5_VERSION; // Version SOCKS5
    buf[1] = 0x01;           // Nombre de méthodes d'authentification
    buf[2] = 0x00;           // Méthode "Pas d'authentification"
    if (send(con->sock, buf, 3, 0) < 0) {
        perror("send");
        close(con->sock);
        return (1);
    }
    memset(buf, 0, 256);
    ///printf("Waiting...\n");
    // Recevoir la réponse du proxy
    if (recv(con->sock, buf, 2, 0) < 0) {
        perror("recv");
        close(con->sock);
        return (1);
    }
    ///printf("Sock5 version : [%d]\n", buf[0]);
    ///printf("Response : [%d - ", buf[1]);
    switch (buf[1])
    {
        case 0:
            ///printf("NO AUTHENTICATION REQUIRED]\n");
            break;
        case 1:
            ///printf("GSSAPI]\n");
            break;
        case 2:
            ///printf("USERNAME/PASSWORD]\n");
            break;
        case 0xff:
            ///printf("NO ACCEPTABLE METHODS]\n");
            break;
        default:
        {
            if (buf[1] >= 3 && buf[1] <= 0x7f)
                ;///printf("IANA ASSIGNED]\n");
            else if (buf[1] >= 0x80 && buf[1] <= 0xfe)
                ;///printf("RESERVED FOR PRIVATE METHODS]\n");
            else
                ;///printf("Unknown]\n");
        }
    }
    // Vérifier la réponse
    if (buf[0] != SOCKS5_VERSION || buf[1] != 0x00) {
        printf("SOCKS5 authentication failed\n");
        close(con->sock);
        return (1);
    }

    // Préparer la requête de connexion
    len = strlen(host);
    buf[0] = SOCKS5_VERSION; // Version
    buf[1] = SOCKS5_CMD_CONNECT; // Command
    buf[2] = SOCKS5_RESERVED; // Reserved
    buf[3] = SOCKS5_ATYP_DOMAIN; // Address type (domain)
    buf[4] = len; // Length of domain name
    memcpy(&buf[5], host, len); // Domain name
    // Set the destination port (2 bytes, network byte order)
    buf[5 + len] = (con->port >> 8) & 0xFF; // High byte
    buf[6 + len] = con->port & 0xFF;        // Low byte

    ///printf("Sending request.\n");
    ///printf("[%d][%d][%d][%d]\n", buf[0], buf[1], buf[2], buf[3]);
    ///printf("Length [%d]\n", buf[4]);
    ///debug_string(buf + 5, buf[4]);
    ///printf("Port [%d]\n", con->port);
    // Envoyer la requête de connexion
    if (send(con->sock, buf, 7 + len, 0) < 0)
    {
        perror("send");
        close(con->sock);
        return (1);
    }

    ///printf("Waiting...\n");
    // Recevoir la réponse du proxy
    if (recv(con->sock, buf, 10, 0) < 0)
    {
        perror("recv");
        close(con->sock);
        return (1);
    }

    ///printf("Received.\n");
    // Vérifier la réponse
    ///printf("Sock5 version : [%d]\n", buf[0]);
    ///printf("Response : [%d]\n", buf[1]);
    if (buf[1] != 0x00) {
        printf("SOCKS5 connection failed\n");
        close(con->sock);
        net_socks5_display_reply(buf[1]);
        return (1);
    }

    ///printf("Address type of following address: ");
    switch (buf[3])
    {
        case 1:
            ;///printf("IPv4\n");
            break;
        case 2:
            ;///printf("Domain name\n");
            break;
        case 3:
            ;///printf("IPv6\n");
            break;
        default:
            ;///printf("Unknown [%d]\n", buf[3]);
    }

    // Address type
    unsigned char atyp = buf[3];
    char bound_address[INET6_ADDRSTRLEN]; // Buffer for the bound address
    unsigned short bound_port;

    // Parse the bound address based on the address type
    if (atyp == 0x01) { // IPv4
        struct in_addr addr;
        memcpy(&addr, &buf[4], sizeof(addr));
        inet_ntop(AF_INET, &addr, bound_address, sizeof(bound_address));
        bound_port = (buf[8] << 8) | buf[9]; // Port in network byte order
    } else if (atyp == 0x03) { // Domain name
        unsigned char domain_length = buf[4];
        memcpy(bound_address, &buf[5], domain_length);
        bound_address[domain_length] = '\0'; // Null-terminate the string
        bound_port = (buf[5 + domain_length] << 8) | buf[6 + domain_length];
    } else if (atyp == 0x04) { // IPv6
        struct in6_addr addr6;
        memcpy(&addr6, &buf[4], sizeof(addr6));
        inet_ntop(AF_INET6, &addr6, bound_address, sizeof(bound_address));
        bound_port = (buf[20] << 8) | buf[21]; // Port in network byte order
    } else {
        printf("Unsupported address type: %d\n", atyp);
        return (1); // Unsupported address type
    }

    // Print the bound address and port
    ///printf("Connected to %s:%u\n", bound_address, bound_port);
    return (0);
}

int             net_connect(t_net_connection *con)
{
    int         ret_connect;

    if (!con || con->connected == 1 || con->sock < 3)
        return (1);
    // Mettre le socket en mode non-bloquant
    /// Mettre le socket en mode non-bloquant
    /*
    if (0 && fcntl(con->sock, F_SETFL, O_NONBLOCK) < 0)
    {
        perror("Échec de fcntl");
        close(con->sock); // Fermez le socket si fcntl échoue
        return (1);
    }
    */
    #ifdef SSL_ENABLED
    if (con->ssl_enabled)
    {
        init_openssl();
        con->ctx = create_context();
        configure_context(con->ctx);
        // Create SSL connection
        if (!(con->ssl = SSL_new(con->ctx)))
            return (1);
        if (con->hostname)
            SSL_set_tlsext_host_name(con->ssl, con->hostname);
        SSL_set_fd(con->ssl, con->sock);
    }
    #endif
    if (url_is_ipv6(con->ip))
    {
        // connect the client socket to server socket
        if ((ret_connect = connect(con->sock, (SA*)&con->server_6, sizeof(con->server_6))) != 0)
        {
            printf("Connect failed to [%s][%d].\n", con->ip, ret_connect);
            #ifdef _WIN32
            closesocket(con->sock);
            WSACleanup();
            #else
            close(con->sock);
            #endif
            return (1);
        }
    }
    else if (url_is_ipv4(con->ip))
    {
        // connect the client socket to server socket
        if ((ret_connect = connect(con->sock, (struct sockaddr *)&con->server, sizeof(con->server))) != 0)
        {
            printf("Connect failed to [%s][%d].\n", con->ip, ret_connect);
            #ifdef _WIN32
            closesocket(con->sock);
            WSACleanup();
            #else
            close(con->sock);
            #endif
            return (1);
        }
    }
    if (con->protocol == PROTOCOL_SOCKS5 && con->onion)
    {
        char *onion;
        onion = url_get_domain(con->onion);
        if (net_socks5_connect_host(con, con->onion))
        {
            FREE(onion);
            printf("Connect Socks5 failed.\n");
            #ifdef _WIN32
            closesocket(con->sock);
            WSACleanup();
            #else
            close(con->sock);
            #endif
            return (1);
        }
        con->connected = 1;
        FREE(onion);
    }
    else
    {
        con->connected = 1;
        /*
        //////////////////////////////////////////////////////////////////////
        // Utiliser select pour attendre la connexion
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(con->sock, &fdset);

        tv.tv_sec = TIMEOUT * 3; // Temps d'attente en secondes
        tv.tv_usec = 0;      // Temps d'attente en microsecondes

        ret_connect = select(con->sock + 1, NULL, &fdset, NULL, &tv);
        DEBUG //
        if (ret_connect > 0) {
            // Vérifier si la connexion a réussi
            int so_error;
            socklen_t len = sizeof(so_error);
            if ((ret_connect = getsockopt(con->sock, SOL_SOCKET, SO_ERROR, &so_error, &len)) < 0) {
            ///if (getsockopt(con->sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                perror("getsockopt");
                printf("RETCONNECT [%d]\n", ret_connect);
                return (1); // Erreur lors de la vérification de l'erreur de socket
            }
            if (so_error == 0) {
                printf("Connexion réussie\n");
                con->connected = 1; // Marquer comme connecté
                //return (0); // Connexion réussie
            } else {
                errno = so_error;
                printf("Erreur de connexion : %s\n", strerror(so_error));
                return (1); // Erreur de connexion
            }
        } else if (ret_connect == 0) {
            errno = ETIMEDOUT; // Timeout
            printf("Timeout lors de la connexion à [%s].\n", con->ip);
            return (1); // Timeout
        } else {
            perror("select");
            return (1); // Erreur lors de select
        }
        */
    }
    //////////////////////////////////////////////////////////////////////
    #ifdef SSL_ENABLED
    if (con->ssl_enabled && con->connected == 1)
    {
        // Establish SSL connection
        if (SSL_connect(con->ssl) <= 0)
        {
            ERR_print_errors_fp(stderr); //
            return (1);
        }
    }
    #endif // SSL_ENABLED
    return (0);
}

int             net_disconnect(t_net_connection *con)
{
    if (!con || con->connected == 0)
        return (1);
    #ifdef SSL_ENABLED
    if (con->ssl_enabled)
    {
        con->ssl_enabled = 0;
        SSL_free(con->ssl);
        SSL_CTX_free(con->ctx);
        cleanup_openssl();
    }
    #endif
    #ifdef _WIN32
    closesocket(con->sock);
    WSACleanup();
    #else
    close(con->sock);
    #endif
    con->connected = 0;
    if (con->onion)
    {
        FREE(con->onion);
        con->onion = NULL;
    }
    return (0);
}

int             net_send(t_net_connection *con, char *data, uint *length)
{
    uint        message_len;

    if (!con)
        return (1);
    if (con->connected == 0 && net_connect(con))
        return (1);
    #ifdef SSL_ENABLED
    if (con->ssl_enabled)
    {
        SSL_write(con->ssl, data, strlen(data));
    }
    else
    #endif
    {
        #ifdef _WIN32
        if (length)
            message_len = *length;
        else
            message_len = strlen(data);
        write(con->sock, data, message_len);
        #else
        if (length)
            message_len = *length;
        else
            message_len = strlen(data);
        if (send(con->sock, data, message_len, 0) == -1)//SOCKET_ERROR)
        {
            printf("Erreur lors de l'envoi\n");
            printf("Erreur: %s\n", strerror(errno));
            printf("CON->SOCK [%d]\n", con->sock); //
            return (1);
        }
        #endif
    }
    return (0);
}

typedef struct s_http_response
{
    char            http_version[STRING_SIZE];
    char            message[STRING_SIZE];
    uint            code;
    char            content_type[STRING_SIZE];
    uint            content_length;
    struct s_buf    header;
    struct s_buf    content;
    char            *buf;
}               t_http_response;

void                           http_display_response(t_http_response *response)
{
    if (!response)
        return ;
    printf("Version: %s\n", response->http_version);
    printf("Code [%d]\n", response->code);
    printf("Message \"%s\"\n", response->message);
    printf("Content-type [%s]\n", response->content_type);
    printf("Headers\n");
    buffer_display_param_list(&response->header);
    ///printf("CONTENT\n-----------------------\n%s\n", response->buf);
}

/////////////////////////////////////////////////////

/// JSON
typedef struct s_json_node
{
    struct s_json_node *parent;
    struct s_buf       child;
    struct s_buf       data;
}               t_json_node;

void            *json_free(t_json_node *node)
{
    t_buf_param *param;
    t_json_node *child;
    int         i;

    if (!node)
        return (NULL);
    i = -1;
    while (++i < node->data.size)
    {
        param = *((t_buf_param **)buffer_get_index(&node->data, i));
        buffer_free_param(param);
    }
    buffer_free(&node->data);
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_json_node **)buffer_get_index(&node->child, i));
        json_free(child);
    }
    buffer_free(&node->child);
    FREE(node);
    return (NULL);
}

t_buf_param         *buffer_new_param_json(char *json, char **end)
{
    struct s_buf            string;
    t_buf_param             *param;
    char                    *endofstring;

    if (!json || !(param = ALLOC(sizeof(struct s_buf_param))))
        return (NULL);
    memset(param, 0, sizeof(struct s_buf_param));
    string = buffer_new(1, 0);
    param->data.blocksize = 1;
    json = string_skipblank(json);
    if (*json == '\'' || *json == '"')
    {
        string.buf = html_new_string(json, &endofstring);
        strncpy(param->name, string.buf, endofstring - json);
        buffer_free(&string);
    }
    else
    {
        endofstring = string_goto(json, ':') - 1;
        while (is_blank(*endofstring))
            endofstring--;
        endofstring++;
        if (endofstring < json || endofstring - json >= STRING_SIZE)
        {
            FREE(param);
            return (NULL);
        }
        strncpy(param->name, json, endofstring - json);
    }
    json = endofstring + 1;
    if (*json == ':')
        json++;
    json = string_skipblank(json);
    if (*json && *json != '\'' && *json != '"')
    {
        endofstring = json;
        while (*endofstring != ' ' && *endofstring != ',' && *endofstring != '}' && is_printable(*endofstring))
            endofstring++;
        string.blocksize = 1;
        string.size = endofstring - json;
        string.buf = json;
        buffer_concat(&param->data, &string);
        json = endofstring;
    }
    else
    {
        string.blocksize = 1;
        string.buf = html_new_string(json, &json);
        string.size = strlen(string.buf);
        buffer_concat(&param->data, &string);
        buffer_free(&string);
        if (*json)
            json++;
    }
    if (end)
        *end = json;
    return (param);
}

void                json_link_parent(t_json_node *node, t_json_node *parent)
{
    t_json_node     *child;
    uint            i;

    if (!node)
        return ;
    node->parent = parent;
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_json_node **)buffer_get_index(&node->child, i));
        json_link_parent(child, node);
    }
}

t_json_node         *json_new_node(char *json, t_json_node *parent, char **end)
{
    t_json_node     *node;
    t_json_node     *child;
    t_buf_param     *param;

    if (!(node = ALLOC(sizeof(struct s_json_node))))
        return (NULL);
    memset(node, 0, sizeof(struct s_json_node));
    node->child = buffer_new(sizeof(t_json_node), 0);
    node->data = buffer_new(sizeof(t_buf_param), 0);
    while (*json && *json != '}')
    {
        json = string_skipblank(json);
        if (*json == ',')
        {
            json++;
            continue;
        }
        if (*json == '{')
        {
            // Block
            if (!(child = json_new_node(json + 1, node, &json)))
                return (json_free(node));
            if (buffer_push(&node->child, &child))
                return (json_free(node));
            json++;
        }
        else if (*json != '}')
        {
            // Variable
            if (!(param = buffer_new_param_json(json, &json)))
                return (json_free(node));
            if (buffer_push(&node->data, &param))
                return (json_free(node));
        }
    }
    if (end)
        *end = json;
    if (!parent)
        json_link_parent(node, NULL);
    return (node);

}

char            *json_tostring(t_json_node *node)
{
    t_json_node     *child;
    t_buf_param     *param;
    char            *buffer;
    char            *string;
    uint            i;

    if (!node)
        return (NULL);
    buffer = NULL;
    if (node->parent)
        buffer = string_stradd(buffer, "{");
    i = -1;
    while (++i < node->data.size)
    {
        param = *((t_buf_param **)buffer_get_index(&node->data, i));
        if (!(string = buffer_param_tostring_json(param)))
        {
            FREE(buffer);
            return (NULL);
        }
        buffer = string_stradd(buffer, string);
        FREE(string);
        if (i + 1 < node->data.size || node->child.size != 0)
            buffer = string_stradd(buffer, ", ");
    }
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_json_node **)buffer_get_index(&node->child, i));
        if (!(string = json_tostring(child)))
        {
            FREE(buffer);
            return (NULL);
        }
        buffer = string_stradd(buffer, string);
    }
    if (node->parent)
        buffer = string_stradd(buffer, "}");
    return (buffer);
}

struct s_buf        json_get_param(t_json_node *node, char *paramname)
{
    struct s_buf    list;
    struct s_buf    childlist;
    t_json_node     *child;
    t_buf_param     *param;
    uint            i;

    memset(&list, 0, sizeof(struct s_buf));
    if (!node || !param)
        return (list);
    list.blocksize = sizeof(t_buf_param);
    i = -1;
    while (++i < node->data.size)
    {
        param = *((t_buf_param **)buffer_get_index(&node->data, i));
        if (strncmp(param->name, param->data.buf, STRING_SIZE) == 0 &&
            buffer_push(&list, &param))
        {
            buffer_free(&list);
            return (list);
        }
    }
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_json_node **)buffer_get_index(&node->child, i));
        childlist = json_get_param(child, paramname);
        if (buffer_concat(&list, &childlist))
        {
            buffer_free(&childlist);
            buffer_free(&list);
            return (list);
        }
        buffer_free(&childlist);
    }
    return (list);
}

void            *buffer_free_json(t_buf *buf)
{
    uint        i;
    t_json_node *node;

    if (!buf)
        return (NULL);
    i = -1;
    while (++i < buf->size)
    {
        node = *((t_json_node **)buffer_get_index(buf, i));
        json_free(node);
    }
    return (buffer_free(buf));
}

///////////////////////////////////////////////////////////

void            http_free_response(t_http_response *response)
{
    uint            i;
    t_buf_param     *param;

    if (!response)
        return ;
    i = -1;
    while (++i < response->header.size)
    {
        param = *((t_buf_param **)buffer_get_index(&response->header, i));
        buffer_free_param(param);
    }
    buffer_free(&response->header);
    if (response->buf)
        FREE(response->buf);
    if (strncasecmp(response->content_type, "application/json", strlen("application/json")) == 0)
        buffer_free_json(&response->content);
    else
        buffer_free(&response->content);
    memset(response, 0, sizeof(struct s_http_response));
}

t_buf_param         *buffer_new_param_http(char *http)
{
    char            *endofstring;
    char            *ptr;
    t_buf_param     *param;

    if (!http)
        return (NULL);
    if (!(endofstring = string_goto(http, ':')))
        return (NULL);
    if (!(param = ALLOC(sizeof(struct s_buf_param))))
        return (NULL);
    memset(param, 0, sizeof(struct s_buf_param));
    if (endofstring - http > STRING_SIZE)
    {
        FREE(param);
        return (NULL);
    }
    memcpy(param->name, http, endofstring - http);
    if (!(ptr = string_skipblank(endofstring + 1)))
    {
        FREE(param);
        return (NULL);
    }
    if (*ptr == '\'' || *ptr == '"')
    {
        endofstring = string_goto(ptr, '\n');
        if (!(param->data.buf = html_new_string(ptr, NULL)))
        {
            FREE(param);
            return (NULL);
        }
        param->data.blocksize = 1;
        param->data.size = strlen(param->data.buf);
    }
    else
    {
        endofstring = string_goto_nonnull(ptr, '\n');
        if (!(param->data.buf = ALLOC((endofstring - ptr) + 1)))
        {
            FREE(param);
            return (NULL);
        }
        param->data.blocksize = 1;
        param->data.size = endofstring - ptr;
        memset(param->data.buf, 0, (endofstring - ptr) + 1);
        memcpy(param->data.buf, ptr, endofstring - ptr);
    }
    return (param);
}

char                           *string_stringify(char *str, char special)
{
    char        *formated;
    char        *ret;
    uint        count;
    uint        length;

    if (!str)
        return (NULL);
    count = string_count_char(str, '"', strlen(str));
    length = strlen(str) + count;
    if (!(formated = ALLOC(length)))
        return (NULL);
    ret = formated;
    memset(formated, 0, length);
    while (*str)
    {
        if (*str == special)
        {
            *formated = '\\';
            formated++;
            *formated = special;
            formated++;
            str++;
        }
        else
            *(formated++) = *(str++);
    }
    return (ret);
}

struct s_http_response         http_new_response(char *http, uint *length)
{
    t_buf_param                 *param;
    struct s_http_response      response;
    char                        *res;
    char                        *ptr;
    char                        *tmp;
    char                        *endofstring;

    memset(&response, 0, sizeof(struct s_http_response));
    if (!http)
        return (response);
    if (length)
    {
        ptr = http - 1;
        while (*(++ptr))
            if (*ptr == '\n' && *(ptr + 1) == '\n')
            {
                *length = ptr - http;
                break;
            }
    }
    if (!(res = string_remove_char(http, '\r')))
        return (response);
    ptr = res;
    if (!(endofstring = string_goto(ptr, ' ')))
    {
        FREE(res);
        return (response);
    }
    if (endofstring - ptr > STRING_SIZE)
    {
        FREE(res);
        return (response);
    }
    // Version
    memcpy(response.http_version, ptr, endofstring - ptr);
    if (strncasecmp(response.http_version, "HTTP", strlen("HTTP")) != 0)
    {
        printf("Not HTTP\n");
        FREE(res);
        return (response);
    }
    ptr = endofstring + 1;
    // Code
    response.code = atoi(ptr);
    endofstring = string_goto(ptr, '\n');
    if (!*endofstring)
    {
        FREE(res);
        return (response);
    }
    ptr = string_goto(ptr, ' ');
    // Message
    if ((endofstring - 1) - ptr < STRING_SIZE)
        memcpy(&response.message, ptr + 1, (endofstring - 1) - ptr);
    // Headers
    response.header = buffer_new(sizeof(t_buf_param), 0);
    ptr = endofstring;
    while (is_alphanum(*(++ptr)))
    {
        if (!(param = buffer_new_param_http(ptr)))
        {
            FREE(res);
            http_free_response(&response);
            return (response);
        }
        if (!(tmp = string_stringify(param->data.buf, '"')))
        {
            FREE(res);
            http_free_response(&response);
            return (response);
        }
        FREE(param->data.buf);
        param->data.buf = tmp;
        param->data.size = strlen(tmp);
        if (strncasecmp(param->name, "Content-Type", strlen("Content-Type")) == 0)
        {
            strncpy(response.content_type, param->data.buf, STRING_SIZE);
            buffer_push(&response.header, &param);
            //buffer_free_param(param);
            //FREE(param);
        }
        else if (strncasecmp(param->name, "Content-Length", strlen("Content-Length")) == 0)
        {
            response.content_length = atoi(param->data.buf);
            buffer_push(&response.header, &param);
            //buffer_free_param(param);
            //FREE(param);
        }
        else
            buffer_push(&response.header, &param);
        ptr = string_goto_nonnull(ptr, '\n');
        if (0 && !ptr)
        {
            FREE(res);
            http_free_response(&response);
            return (response);
        }
    }
    // Content
    /// TODO
    /// Batman
    if (0 && response.content_length != 0)
    {
        ///endofstring = string_goto(ptr, '\0');
        endofstring = ptr + response.content_length;
        if (!(response.buf = ALLOC(response.content_length + 1)))
        {
            FREE(res);
            http_free_response(&response);
            return (response);
        }
        memset(response.buf, 0, response.content_length + 1);
        memcpy(response.buf, ptr, response.content_length);
    }
    else
    {
        response.content_length = strlen(ptr);
        printf("CONTENT LENGTH : %u\n", response.content_length); ///
        response.buf = string_strdup(ptr);
    }
    FREE(res);
    return (response);
}

char            *net_recv(t_net_connection *con, uint *length)
{
    int                     rd;
    struct s_buf            readed;
    struct s_buf            string;
    #define NET_BUF_SIZE 2920
    char                    buff[NET_BUF_SIZE];
    struct s_http_response  response;
    char                    *content_length_string;
    uint                    content_length;

    if (!con) // Netcode
        return (NULL);
    if (con->connected == 0 && net_connect(con))
        return (NULL);
    content_length = -1;
    readed.blocksize = 1;
    readed.buf = &buff;
    readed.size = 0;
    string = buffer_new(1, 0);
    ///printf("Receiving\n");
    #ifdef _WIN32
    while (
           (con->ssl_enabled == 0
           && (
           (content_length == -1 && (rd = recv(con->sock, buff, NET_BUF_SIZE)) > 0) ||
           (readed.size < content_length && (rd = recv(con->sock, buff, NET_BUF_SIZE)) > 0)
               )) ||
           (con->ssl_enabled == 1
            && (
           (content_length == -1 && (rd = SSL_read(con->ssl, buff, NET_BUF_SIZE)) > 0) ||
           (readed.size < content_length && (rd = SSL_read(con->ssl, buff, NET_BUF_SIZE)) > 0)
                )
            )
           )
    #else
    while (
           (con->ssl_enabled == 0
           && (
           (content_length == -1 && (rd = read(con->sock, buff, NET_BUF_SIZE)) > 0) ||
           (readed.size < content_length && (rd = read(con->sock, buff, NET_BUF_SIZE)) > 0)
               )) ||
           (con->ssl_enabled == 1
            && (
           (content_length == -1 && (rd = SSL_read(con->ssl, buff, NET_BUF_SIZE)) > 0) ||
           (readed.size < content_length && (rd = SSL_read(con->ssl, buff, NET_BUF_SIZE)) > 0)
                )
            )
           )
    #endif
    {
        if (readed.size == 0)
        {
            // Superman
            uint http_length;
            response = http_new_response(buff, &http_length);
            if (response.code != 0)
            {
                ///http_display_response(&response); //
                if ((content_length_string = buffer_param_get_var_buf(&response.header, "Content-Length")))
                    content_length = atoi(content_length_string) + http_length - 64; // BUG -64 ???
            }
            //printf("content-length = %d\n", content_length); //
            http_free_response(&response);
        }
        ///printf("> %u", rd);
        readed.size = rd;
        ///if (content_length != -1)
        ///    printf(" (%u/%u)", readed.size, content_length);
        ///printf("\n");
        if (length)
            *length += rd;
        if (buffer_concat(&string, &readed))
        {
            buffer_free(&string);
            return (NULL);
        }
    }
    ///printf("\n");
    /** // TIMEOUT
    if (rd == -1)
    {
        printf("Transmission error\n");
        buffer_free(&string);
        return (NULL);
    }
    */
    printf("Received %u bytes\n", string.size);
    return ((char *)string.buf);
}

char            *net_send_recv(t_net_connection *con, char *data, uint *send_length, uint *recv_length)
{
    if (net_send(con, data, send_length))
        return (NULL);
    return (net_recv(con, recv_length));
}

/////////////////////////////////////////////////////

typedef struct s_http_content
{
    char            type[STRING_SIZE];
    struct s_buf    data;
}               t_http_content;

uint                    http_content_type_size(char *type)
{
    if (strncmp(type, "application/x-www-form-urlencoded", strlen("application/x-www-form-urlencoded")) == 0)
        return (sizeof(t_buf_param));
    if (strncmp(type, "application/json", strlen("application/json")) == 0)
        return (sizeof(t_json_node));
    if (strncmp(type, "text/", strlen("text/")) == 0)
        return (sizeof(char));
    return (sizeof(char));
}

void                    *buffer_free_param_list(t_buf *list)
{
    uint        i;
    t_buf_param *param;

    if (!list)
        return (NULL);
    i = -1;
    while (++i < list->size)
    {
        param = *((t_buf_param **)buffer_get_index(list, i));
        buffer_free_param(param);
        FREE(param);
    }
    return (NULL);
}

void                    http_free_content(t_http_content *content)
{
    if (!content)
        return ;
    if (strncmp(content->type, "application/x-www-form-urlencoded", strlen("application/x-www-form-urlencoded")) == 0)
        buffer_free_param_list(&content->data);
    else if (strncmp(content->type, "application/x-www-form-urlencoded", strlen("application/x-www-form-urlencoded")) == 0)
        buffer_free_json(&content->data);
    else
        buffer_free(&content->data);
}

struct s_http_content   http_new_content(char *type, t_buf *data)
{
    struct s_http_content       content;
    uint                        blocksize;

    strncpy(content.type, type, STRING_SIZE - 1);
    blocksize = http_content_type_size(content.type);
    content.data = buffer_new(blocksize, 0);
    buffer_concat(&content.data, data);
    return (content);
}

typedef struct s_http_request
{
    char                    method[STRING_SIZE];
    char                    *url;
    struct s_buf            param;
    struct s_buf            header;
    struct s_http_content   content;
}               t_http_request;

void                    http_free_request(t_http_request *request)
{
    if (!request)
        return ;
    if (request->url)
        FREE(request->url);
    buffer_free_param_list(&request->param);
    buffer_free_param_list(&request->header);
    http_free_content(&request->content);
}

struct s_http_request   http_new_request(char *url, char *method, t_buf *param, t_buf *header, t_http_content *content)
{
    struct s_http_request   request;

    memset(&request, 0, sizeof(struct s_http_request));
    if (!method || !url)
        return (request);
    strncpy(request.method, method, STRING_SIZE - 1);
    if (!(request.url = string_strdup(url)))
        return (request);
    if (param)
    {
        request.param = buffer_new(sizeof(t_buf_param), 0);
        buffer_concat(&request.param, param);
    }
    if (header)
    {
        request.header = buffer_new(sizeof(t_buf_param), 0);
        buffer_concat(&request.header, header);
    }
    if (content)
        request.content = *content;
    return (request);
}

#include <stdarg.h>
struct s_buf    buffer_new_param_list(int count, ...)
{
    struct s_buf    list;
    va_list         args;
    t_buf_param     *param;
    int             i;

    va_start(args, count);
    list = buffer_new(sizeof(t_buf_param), 0);
    i = -1;
    while (++i < count)
    {
        if (!(param = buffer_new_param(va_arg(args, char *), NULL)))
            return (list);
        buffer_push(&list, &param);
    }
    va_end(args);
    return (list);
}

int         url_get_port(char *url)
{
    char        *proto;
    int         port;
    char        *endofstring;

    if (!(proto = url))
        return (-1);
    if (string_count_char(url, ':', url - string_goto(url, '/')) == 0) // Testing
        return (80);
    while (*url && *url != ':')
        url++;
    if (!*url)
        return (-1);
    url++;
    endofstring = url;
    while (*endofstring && *endofstring == '/')
        endofstring++;
    if (!*endofstring || endofstring - url != 2 || !(url = endofstring))
    {
        while (*proto && *proto != ':')
            proto++;
        if (is_numeric(*(proto + 1)))
            return (atoi(proto + 1));
        return (-1);
    }
    endofstring = url;
    while (*endofstring && *endofstring != '/' && *endofstring != ':')
        endofstring++;
    if (!*endofstring || *endofstring == '/' || !is_numeric(*(endofstring + 1)))
    {
        if (!(proto = url_get_proto(proto)))
            return (-1);
        port = url_get_port_proto(proto);
        FREE(proto);
        if (port == -1)
            return (80);
        return (port);
    }
    return (atoi(endofstring + 1));
}

char     *url_get_route(char *url)
{
    char        *route;
    char        *endofstring;
    uint        size;

    if (!url)
        return (NULL);
    while (*url && *url != ':')
        url++;
    if (!*url)
        return (NULL);
    url++;
    endofstring = url;
    while (*endofstring && *endofstring == '/')
        endofstring++;
    if (!*endofstring || endofstring - url != 2 || !(url = endofstring))
        return (NULL);
    endofstring = url;
    while (*endofstring && *endofstring != '/')
        endofstring++;
    if (!*endofstring)
        return (string_strdup("/"));
    url = endofstring;
    while (*endofstring && *endofstring != '#') // Bad request
        endofstring++;
    size = endofstring - url;
    //else
    //    size = strlen(url);
    if (!(route = ALLOC(size + 1)))
        return (NULL);
    memset(route, 0, size + 1);
    return (strncpy(route, url, size));
}

int             url_is_https(char *url)
{
    char        *proto;

    if (!(proto = url_get_proto(url)))
        return (-1);
    if (strncasecmp(proto, "https\0", strlen("https") + 1) == 0)
    {
        FREE(proto);
        return (1);
    }
    if (strncasecmp(proto, "http\0", strlen("http") + 1) == 0)
    {
        FREE(proto);
        return (0);
    }
    FREE(proto);
    return (-1);
}

struct s_buf    url_get_param(char *url)
{
    struct s_buf        list;
    t_buf_param         *param;
    char                *route;
    char                *ptr;

    list = buffer_new(sizeof(t_buf_param), 0);
    if (!url)
        return (list);
    if (!(route = url_get_route(url)))
        return (list);
    ptr = route + 1;
    while (*ptr)
    {
        if (!(param = buffer_new_param(ptr, &ptr)) || buffer_push(&list, param))
        {
            FREE(route);
            return (list);
        }
        while (*ptr && *ptr != '&')
            ptr++;
        if (*ptr)
            ptr++;
    }
    FREE(route);
    return (list);
}

char        *net_resolve_domain(const char *domain, int ipindex)
{
    uint            i;
    char            *ret;
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN]; // Buffer to hold the IP address string

    if (!domain)
        return (NULL);
    #ifdef _WIN32
    WSADATA         wsaData;
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return (NULL);
    }
    #endif // _WIN32

    ret = NULL;
    // Set up the hints structure
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_UNSPEC means we don't care if it's IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
    hints.ai_flags |= AI_CANONNAME; // Test

    // Get the address info
    if ((status = getaddrinfo(domain, NULL, &hints, &res)) != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(status));
        return (NULL);
    }
    i = 0;
    // Loop through all the results and convert the IP to a string
    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        // Get the pointer to the address itself
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
        if (ipindex == -1 || i == ipindex)
        {
            // Convert the IP to a string and print it
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            ///printf("Resolved IP: %s\n", ipstr);
            ret = string_strdup(ipstr);
            break;
        }
        i++;
    }
    // Free the linked list
    freeaddrinfo(res);
    if (i < ipindex)
        return (NULL);
    return (ret);
}

int                 url_host_is_onion(char *host)
{
    char            *prev;
    char            *ptr;

    if (!host)
        return (0);
    ptr = host + strlen(host);
    while (*ptr != '.')
        ptr--;
    if (strncmp(ptr, ".onion", strlen(".onion")) != 0)
        return (0);
    if (string_count_char(host, '.', strlen(host)) == 1)
    {
        ptr = host;
        while (*ptr != '.')
        {
            if (!is_alphanum(*ptr))
                return (0);
            if (!*ptr)
                return (0);
            ptr++;
        }
    }
    else
    {
        ptr--;
        while (*ptr != '.')
        {
            if (!is_alphanum(*ptr))
                return (0);
            ptr--;
        }
    }
    return (1);
}

struct s_net_connection         url_new_connection(char *url, int ipindex)
{
    struct s_net_connection     con;
    char                        *host;
    char                        *ip;

    memset(&con, 0, sizeof(struct s_net_connection));
    if (!(host = url_get_host(url)))
        return (con);
    if (url_is_ipv4(host) || url_is_ipv6(host))
    {
        if (!(ip = string_strdup(host)))
        {
            FREE(host);
            return (con);
        }
        con = net_new_connection(ip, NULL, url_get_port(url), url_is_https(url));
        FREE(ip);
    }
    else if (url_host_is_onion(host))
    {
        ///printf("Establishing TOR connection.\n");
        // Onion
        con = net_new_onion_connection(host, url_get_port(url), url_is_https(url));
        FREE(host);
    }
    else
    {
        if (!(ip = net_resolve_domain(host, ipindex)))
        {
            FREE(host);
            return (con);
        }
        con = net_new_connection(ip, host, url_get_port(url), url_is_https(url));
        FREE(ip);
        FREE(host);
    }
    return (con);
}

void                           http_display_request(t_http_request *request)
{
    if (!request)
        return ;
    printf("URL [%s][%s]\n", request->method, request->url);
    printf("Param:\n");
    buffer_display_param_list(&request->param);
    printf("Header:\n");
    buffer_display_param_list(&request->header);
    printf("Content @ %p\n", &request->content);
}

void            net_free_connection(t_net_connection *con)
{
    net_disconnect(con);
    if (con->hostname)
        FREE(con->hostname);
}

char            *http_send_request(t_http_request *request, uint *recv_length)
{
    char                    *http;
    struct s_net_connection con;
    int                     i;
    int                     ipindex;
    t_json_node             *json;
    t_buf_param             *param;
    char                    *string;
    char                    *route;
    char                    *host;
    char                    *hostname;
    char                    *ret;

    if (!request)
        return (NULL);
    #ifndef SSL_ENABLED
    if (url_is_https(request->url) == 1)
        return (NULL);
    #endif
    ipindex = 0;
    con = url_new_connection(request->url, ipindex++);
    while (net_connect(&con))
    {
        net_free_connection(&con);
        if (ipindex > 10)
            return (NULL);
        con = url_new_connection(request->url, ipindex++);
    }
    ///printf("Url [%s]\n", request->url);
    if (!(host = url_get_host(request->url)))
        return (NULL);
    ///printf("Host [%s]\n", host);
    if (!(route = url_get_route(request->url)))
    {
        FREE(host);
        return (NULL);
    }
    ///printf("Route [%s]\n", route);
    http = NULL;
    http = string_stradd(http, request->method);
    http = string_stradd(http, " ");
    http = string_stradd(http, route);
    FREE(route);
    i = -1;
    ///printf("Param :\n");
    while (++i < request->param.size)
    {
        param = *((t_buf_param **)buffer_get_index(&request->param, i));
        ///buffer_display_param(param, 1);
        http = string_stradd(http, param->name);
        http = string_stradd(http, "=");
        http = string_stradd(http, param->data.buf);
        if (i + 1 < request->param.size - 1)
            http = string_stradd(http, "&");
    }
    http = string_stradd(http, " HTTP/1.1\r\n");
    ///printf("Headers :\n");
    if (!url_is_ipv4(request->url) && !buffer_param_get_var_buf_case(&request->header, "Host") && (hostname = url_get_host(request->url)))
    {
        host = string_stradd(NULL, "Host='");
        host = string_stradd(host, hostname);
        host = string_stradd(host, "'");
        FREE(host);
        FREE(hostname);
    }
    /*if (!url_is_ipv4(host))
    {
        http = string_stradd(http, "Host: ");
        http = string_stradd(http, host);
        http = string_stradd(http, "\r\n");
    }
    FREE(host);
    */
    if (strlen(request->content.type) > 0)
    {
        http = string_stradd(http, "Content-Type: ");
        http = string_stradd(http, request->content.type);
        http = string_stradd(http, "\r\n");
    }
    i = -1;
    while (++i < request->header.size)
    {
        param = *((t_buf_param **)buffer_get_index(&request->header, i));
        ///buffer_display_param(param, 1);
        http = string_stradd(http, param->name);
        http = string_stradd(http, ": ");
        http = string_stradd(http, param->data.buf);
        http = string_stradd(http, "\r\n");
    }
    if (strlen(request->content.type) != 0)
    {
        http = string_stradd(http, "\r\n");
        ///printf("Content : [%s]\n", request->content.type);
        if (strncmp(request->content.type, "application/x-www-form-urlencoded", strlen("application/x-www-form-urlencoded")) == 0)
        {
            i = -1;
            while (++i < request->content.data.size)
            {
                param = *((t_buf_param **)buffer_get_index(&request->content.data, i));
                if ((string = buffer_param_tostring_html(param)))
                {
                    http = string_stradd(http, string);
                    FREE(string);
                }
            }
        }
        else if (strncmp(request->content.type, "application/json", strlen("application/json")) == 0)
        {
            i = -1;
            while (++i < request->content.data.size)
            {
                json = *((t_json_node **)buffer_get_index(&request->content.data, i));
                if ((string = json_tostring(json)))
                {
                    http = string_stradd(http, string);
                    FREE(string);
                }
            }
        }
        else if (strncmp(request->content.type, "text/", strlen("text/")) == 0)
        {
            //http = string_stradd(http, request->content.data.buf, request->content.data.size)
            http = string_stradd(http, request->content.data.buf);
        }
    }
    http = string_stradd(http, "\r\n\r\n\r\n");
    ret = net_send_recv(&con, http, NULL, recv_length);
    FREE(http);
    net_free_connection(&con);
    return (ret);
}

int                 url_is_relative(char *url)
{
    char        *proto;

    if (!(proto = url_get_proto(url)))
        return (1);
    FREE(proto);
    return (0);
}

char                *url_get_directory(char *url)
{
    char        *endofstring;
    char        *proto;
    char        *host;

    if (!url)
        return (NULL);
    if (!(host = url_get_host(url)))
        return (NULL);
    if (!(proto = url_get_proto(url)))
    {
        FREE(host);
        return (NULL);
    }
    url += strlen(host) + strlen(proto) + strlen("://");
    FREE(host);
    FREE(proto);
    endofstring = url;
    while (*endofstring)
        endofstring++;
    while (*endofstring != '/')
        endofstring--;
    endofstring++;
    return (string_duplicate(url, endofstring - url));
}

char                *url_directory_up(char *directory)
{
    char            *endofstring;

    if (!(endofstring = directory))
        return (NULL);
    while (*endofstring)
        endofstring++;
    endofstring--;
    if (*endofstring == '/')
        endofstring--;
    while (*endofstring != '/' && endofstring != directory)
        endofstring--;
    return (string_duplicate(directory, endofstring - directory));
}

char                *url_get_full(char *src, char *relative)
{
    char        *full;
    char        *proto;
    char        *host;
    char        *directory;

    if (!src || !relative)
        return (NULL);
    if (!url_is_relative(relative))
        return (string_strdup(relative));
    if (!(host = url_get_host(src)))
        return (NULL);
    if (!(proto = url_get_proto(src)))
    {
        FREE(host);
        return (NULL);
    }
    full = string_stradd(NULL, proto);
    full = string_stradd(full, "://");
    full = string_stradd(full, host);
    FREE(host);
    FREE(proto);
    if (*relative == '/')
        return (string_stradd(full, relative));
    if (!(directory = url_get_directory(src)))
    {
        FREE(full);
        return (NULL);
    }
    if (strncmp(relative, "../", strlen("../")) == 0)
    {
        char        *updir;
        char        *dir;
        char        *relptr;

        relptr = relative;
        dir = string_strdup(directory);
        while (strncmp(relptr, "../", strlen("../")) == 0)
        {
            relptr += strlen("../");
            if (!(updir = url_directory_up(dir)))
            {
                FREE(dir);
                FREE(directory);
                FREE(full);
                return (NULL);
            }
            FREE(dir);
            dir = updir;
        }
        full = string_stradd(full, dir);
        full = string_stradd(full, "/");
        full = string_stradd(full, relptr);
    }
    else
    {
        full = string_stradd(full, directory);
        FREE(directory);
        full = string_stradd(full, relative);
    }
    return (full);
}

struct s_http_response      web_get_page(char *url, t_http_request *out)
{
    struct s_buf            header;
    struct s_http_request   request;
    struct s_http_response  response;
    struct s_http_response  redirect;
    t_buf_param             *param;
    char                    *recv;
    char                    *host;
    char                    *hostname;

    memset(&response, 0, sizeof(struct s_http_response));
    header = buffer_new_param_list(2,
                                   //"Accept='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'",
                                   //"Accept-Encoding='gzip, deflate, br, zstd'",
                                   //"Accept-Language='fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3'",
                                   //"Priority='u=0, i'",
                                   //"Connection='keep-alive'",
                                   "User-Agent='custom'",
                                   "Accept='*/*'");
    if (!url_is_ipv4(url) && (hostname = url_get_host(url)))
    {
        host = string_stradd(NULL, "Host='");
        host = string_stradd(host, hostname);
        host = string_stradd(host, "'");
        param = buffer_new_param(host, NULL);
        buffer_push(&header, &param);
        FREE(host);
        FREE(hostname);
    }
    request = http_new_request(url, "GET", NULL, &header, NULL);
    if (out)
        memcpy(out, &request, sizeof(struct s_http_request));
    if (!(recv = http_send_request(&request, NULL)))
    {
        if (!out)
            http_free_request(&request);
        return (response);
    }
    response = http_new_response(recv, NULL);
    FREE(recv);
    ///if (response.code == 301 || response.code == 302)
    if (response.code >= 300 && response.code < 400)
    {
        char *full_url;
        char *location_url;
        location_url = buffer_param_get_var_buf(&response.header, "location");
        if (url_is_relative(location_url))
            full_url = url_get_full(request.url, location_url);
        else
            full_url = string_strdup(location_url);
        if (strncmp(
                    request.url,
                    full_url,
                    strlen(full_url)
                ) == 0)
        {
            if (out)
            {
                //http_display_request(&request); //
                memcpy(out, &request, sizeof(struct s_http_request));
            }
            else
                http_free_request(&request);
            return (response);
        }
        http_free_request(&request);
        redirect = web_get_page(full_url, out);
        FREE(full_url);
        http_free_response(&response);
        return (redirect);
    }
    if (!out)
        http_free_request(&request);
    return (response);
}

typedef struct  s_web_transmission
{
    uint        origin;
    uint        length;
    char        *data;
}               t_web_transmission;

typedef struct  s_web_port
{
    uint            number; // unsigned Short
    char            service[STRING_SIZE];
    struct s_buf    transmission;
}               t_web_port;

typedef struct  s_web_ip
{
    int             version;
    char            ip[STRING_SIZE];
    struct s_buf    port;
}               t_web_ip;

typedef struct s_web_node
{
    struct s_http_request   request;
    struct s_http_response  response;
    struct s_web_node       *parent;
    struct s_buf            child;
    struct s_html_node      html;
    struct s_web_host       *host;
    pthread_mutex_t         mutex;
}               t_web_node;

typedef struct  s_web_host
{
    t_web_node      *parent;
    char            *name;
    struct s_buf    ip;
}               t_web_host;

void                *web_free_transmission(t_web_transmission *transmission)
{
    if (!transmission)
        return (NULL);
    if (transmission->data)
        FREE(transmission->data);
    return (NULL);
}

void                *web_free_port(t_web_port *port)
{
    t_web_transmission      *transmission;
    uint                    i;

    if (!port)
        return (NULL);
    i = -1;
    while (++i < port->transmission.size)
    {
        transmission = *((t_web_transmission **)buffer_get_index(&port->transmission, i));
        if (!transmission)
            continue;
        web_free_transmission(transmission);
        FREE(transmission);
    }
    buffer_free(&port->transmission);
    return (NULL);
}

void                *web_free_ip(t_web_ip *ip)
{
    t_web_port      *port;
    uint            i;

    if (!ip)
        return (NULL);
    i = -1;
    while (++i < ip->port.size)
    {
        port = *((t_web_port **)buffer_get_index(&ip->port, i));
        if (!port)
            continue;
        web_free_port(port);
        FREE(port);
    }
    buffer_free(&ip->port);
    return (NULL);
}

void                *web_free_host(t_web_host *host)
{
    uint            i;
    t_web_ip        *ip;

    if (!host)
        return (NULL);
    if (host->name)
        FREE(host->name);
    i = -1;
    while (++i < host->ip.size)
    {
        ip = *((t_web_ip **)buffer_get_index(&host->ip, i));
        if (!ip)
            continue;
        web_free_ip(ip);
        FREE(ip);
    }
    buffer_free(&host->ip);
    return (NULL);
}

void            web_free_node(t_web_node *node)
{
    t_web_node  *child;
    uint        i;

    DEBUG //
    http_free_request(&node->request);
    DEBUG //
    http_free_response(&node->response);
    DEBUG //
    i = -1;
    while (++i < node->child.size)
    {
        DEBUG //
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        DEBUG //
        if (!child)
            continue;
        DEBUG //
        web_free_node(child);
        DEBUG //
        FREE(child);
    }
    DEBUG //
    buffer_free(&node->child);
    DEBUG //
    html_free_node_noroot(&node->html);
    DEBUG //
    if (node->host)
    {
        web_free_host(node->host);
        FREE(node->host);
    }
    DEBUG //
}

char            *http_request_export_xml(t_http_request *request)
{
    t_buf_param *param;
    char        buffer[2];
    char        *xml;
    uint        i;

    if (!request)
        return (NULL);
    xml = string_stradd(NULL, "<request method='");
    xml = string_stradd(xml, request->method);
    xml = string_stradd(xml, "' url='");
    xml = string_stradd(xml, request->url);
    xml = string_stradd(xml, "'>");
    i = -1;
    buffer[1] = '\0';
    while (++i < request->param.size)
    {
        xml = string_stradd(xml, "<param ");
        param = *((t_buf_param **)buffer_get_index(&request->param, i));
        xml = string_stradd(xml, param->name);
        xml = string_stradd(xml, "=");
        buffer[0] = string_getdelimiter(param->data.buf);
        xml = string_stradd(xml, buffer);
        xml = string_stradd(xml, param->data.buf);
        xml = string_stradd(xml, buffer);
        xml = string_stradd(xml, "/>");
    }
    i = -1;
    buffer[1] = '\0';
    while (++i < request->header.size)
    {
        xml = string_stradd(xml, "<header ");
        param = *((t_buf_param **)buffer_get_index(&request->header, i));
        xml = string_stradd(xml, param->name);
        xml = string_stradd(xml, "=");
        buffer[0] = string_getdelimiter(param->data.buf);
        xml = string_stradd(xml, buffer);
        xml = string_stradd(xml, param->data.buf);
        xml = string_stradd(xml, buffer);
        xml = string_stradd(xml, "/>");
    }
    xml = string_stradd(xml, "</request>");
    return (xml);
}

char            *http_response_export_xml(t_http_response *response)
{
    char        buffer[STRING_SIZE];
    t_buf_param *header;
    char        *xml;
    char        *tmp;
    uint        i;

    if (!response)
        return (NULL);
    xml = string_stradd(NULL, "<response version='");
    xml = string_stradd(xml, response->http_version);
    xml = string_stradd(xml, "' code='");
    xml = string_stradd(xml, itoa(response->code, buffer, 10));
    xml = string_stradd(xml, "'>");
    i = -1;
    buffer[1] = '\0';
    while (++i < response->header.size)
    {
        xml = string_stradd(xml, "<header ");
        header = *((t_buf_param **)buffer_get_index(&response->header, i));
        xml = string_stradd(xml, header->name);
        xml = string_stradd(xml, "=");
        buffer[0] = string_getdelimiter(header->data.buf);
        xml = string_stradd(xml, buffer);
        xml = string_stradd(xml, header->data.buf);
        xml = string_stradd(xml, buffer);
        xml = string_stradd(xml, "/>");
    }
    xml = string_stradd(xml, "<content>");
    if (response->content_length)
        xml = string_stradd_len(xml, response->buf, response->content_length);
    else
        xml = string_stradd(xml, response->buf);
    xml = string_stradd(xml, "</content>");
    xml = string_stradd(xml, "</response>");
    return (xml);
}

char            *string_hexdump(char *data, uint length)
{
    char        *ptr;
    uint        i;
    char        *hexstring;

    if (!(ptr = data))
        return (NULL);
    hexstring = NULL;
    i = -1;
    while (++i < length)
    {
        hexstring = string_stradd(hexstring, "\\x");
        switch ((*ptr >> 8) & 0x0F)
        {
            case 0:
                hexstring = string_stradd(hexstring, "0");
                break;
            case 1:
                hexstring = string_stradd(hexstring, "1");
                break;
            case 2:
                hexstring = string_stradd(hexstring, "2");
                break;
            case 3:
                hexstring = string_stradd(hexstring, "3");
                break;
            case 4:
                hexstring = string_stradd(hexstring, "4");
                break;
            case 5:
                hexstring = string_stradd(hexstring, "5");
                break;
            case 6:
                hexstring = string_stradd(hexstring, "6");
                break;
            case 7:
                hexstring = string_stradd(hexstring, "7");
                break;
            case 8:
                hexstring = string_stradd(hexstring, "8");
                break;
            case 9:
                hexstring = string_stradd(hexstring, "9");
                break;
            case 10:
                hexstring = string_stradd(hexstring, "a");
                break;
            case 11:
                hexstring = string_stradd(hexstring, "b");
                break;
            case 12:
                hexstring = string_stradd(hexstring, "c");
                break;
            case 13:
                hexstring = string_stradd(hexstring, "d");
                break;
            case 14:
                hexstring = string_stradd(hexstring, "e");
                break;
            case 15:
                hexstring = string_stradd(hexstring, "f");
                break;
        }
        switch (*ptr & 0x0F)
        {
            case 0:
                hexstring = string_stradd(hexstring, "0");
                break;
            case 1:
                hexstring = string_stradd(hexstring, "1");
                break;
            case 2:
                hexstring = string_stradd(hexstring, "2");
                break;
            case 3:
                hexstring = string_stradd(hexstring, "3");
                break;
            case 4:
                hexstring = string_stradd(hexstring, "4");
                break;
            case 5:
                hexstring = string_stradd(hexstring, "5");
                break;
            case 6:
                hexstring = string_stradd(hexstring, "6");
                break;
            case 7:
                hexstring = string_stradd(hexstring, "7");
                break;
            case 8:
                hexstring = string_stradd(hexstring, "8");
                break;
            case 9:
                hexstring = string_stradd(hexstring, "9");
                break;
            case 10:
                hexstring = string_stradd(hexstring, "a");
                break;
            case 11:
                hexstring = string_stradd(hexstring, "b");
                break;
            case 12:
                hexstring = string_stradd(hexstring, "c");
                break;
            case 13:
                hexstring = string_stradd(hexstring, "d");
                break;
            case 14:
                hexstring = string_stradd(hexstring, "e");
                break;
            case 15:
                hexstring = string_stradd(hexstring, "f");
                break;
        }
        ptr++;
    }
    return (hexstring);
}

char            *web_transmission_export_xml(t_web_transmission *transmission)
{
    char                *hexstring;
    char                *xml;
    char                number[STRING_SIZE];

    if (!transmission)
        return (NULL);
    xml = string_stradd(NULL, "<transmission origin='");
    xml = string_stradd(xml, itoa(transmission->origin, number, 10));
    xml = string_stradd(xml, "' length='");
    xml = string_stradd(xml, itoa(transmission->length, number, 10));
    xml = string_stradd(xml, "' type='");
    if (strlen(transmission->data) != transmission->length)
    {
        xml = string_stradd(xml, "binary'>");
        hexstring = string_hexdump(transmission->data, transmission->length);
        xml = string_stradd(xml, hexstring);
        FREE(hexstring);
    }
    else
    {
        xml = string_stradd(xml, "text'>");
        xml = string_stradd(xml, transmission->data);
    }
    xml = string_stradd(xml, "</transmission>");
    return (xml);
}

char            *web_port_export_xml(t_web_port *port)
{
    t_web_transmission  *transmission;
    uint                i;
    char                *xml;
    char                portnum[STRING_SIZE];

    if (!port)
        return (NULL);
    xml = string_stradd(NULL, "<port number='");
    xml = string_stradd(xml, itoa(port->number, portnum, 10));
    xml = string_stradd(xml, "' service='");
    xml = string_stradd(xml, port->service);
    xml = string_stradd(xml, "'>");
    i = -1;
    while (++i < port->transmission.size)
    {
        transmission = *((t_web_transmission **)buffer_get_index(&port->transmission, i));
        xml = string_stradd(xml, web_transmission_export_xml(transmission));
    }
    xml = string_stradd(xml, "</port>");
    return (xml);
}

char            *web_ip_export_xml(t_web_ip *ip)
{
    t_web_port  *port;
    uint        i;
    char        *xml;
    char        versionnum[STRING_SIZE];

    if (!ip)
        return (NULL);
    xml = string_stradd(NULL, "<ip version='");
    xml = string_stradd(xml, itoa(ip->version, versionnum, 10));
    xml = string_stradd(xml, "' source='");
    xml = string_stradd(xml, ip->ip);
    xml = string_stradd(xml, "'>");
    i = -1;
    while (++i < ip->port.size)
    {
        port = *((t_web_port **)buffer_get_index(&ip->port, i));
        xml = string_stradd(xml, web_port_export_xml(port));
    }
    xml = string_stradd(xml, "</ip>");
    return (xml);
}

char            *web_host_export_xml(t_web_host *host)
{
    t_web_ip    *ip;
    char        *xml;
    uint        i;

    if (!host)
        return (NULL);
    xml = string_stradd(NULL, "<host name='");
    xml = string_stradd(xml, host->name);
    xml = string_stradd(xml, "'>");
    i = -1;
    while (++i < host->ip.size)
    {
        ip = *((t_web_ip **)buffer_get_index(&host->ip, i));
        xml = string_stradd(xml, web_ip_export_xml(ip));
    }
    xml = string_stradd(xml, "</host>");
    return (xml);
}

void            web_display_node(t_web_node *node)
{
    t_web_node  *child;
    uint        i;

    printf("-----------------------\n");
    printf("Node @ (%p)\n", node);
    if (!node)
        return ;
    printf("Parent @ (%p)\n", node->parent);
    printf("URL [%s]\n", node->request.url);
    if (node->host)
        printf("\tHOST (%p)\n", node->host);
    printf("Child count #%u\n", node->child.size);
    i = -1;
    while (++i < node->child.size)
    {
        //child = buffer_get_index(&node->child, i);
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        printf("\t%u (%p) ", i, child);
        if (child)
            printf("[%s]", child->request.url);
        printf("\n");
    }
}

char            *web_export_xml(t_web_node *node)
{
    t_web_node          *child;
    char                *xml;
    uint                i;

    if (!node)
        return (NULL);
    xml = string_stradd(NULL, "<web>");
    //web_display_node(node);
    //http_display_request(&node->request); //
    xml = string_stradd(xml, http_request_export_xml(&node->request));
    xml = string_stradd(xml, http_response_export_xml(&node->response));
    xml = string_stradd(xml, web_host_export_xml(node->host));
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        //child = buffer_get_index(&node->child, i);
        xml = string_stradd(xml, web_export_xml(child));
    }
    xml = string_stradd(xml, "</web>");
    return (xml);
}

struct s_buf            buffer_copy_buf(t_buf *buf)
{
    struct s_buf        ret;

    memset(&ret, 0, sizeof(struct s_buf));
    if (!buf)
        return (ret);
    if (!(ret.buf = ALLOC(buf->blocksize * buf->size)))
        return (ret);
    ret.blocksize = buf->blocksize;
    ret.size = buf->size;
    memcpy(ret.buf, buf->buf, buf->blocksize * buf->size);
    return (ret);
}

t_buf_param             *buffer_copy_param(t_buf_param *param)
{
    t_buf_param         *copy;

    if (!param)
        return (NULL);
    if (!(copy = ALLOC(sizeof(struct s_buf_param))))
        return (NULL);
    strncpy(copy->name, param->name, STRING_SIZE - 1);
    copy->data = buffer_copy_buf(&param->data);
    return (copy);
}

struct s_http_response   http_response_import_xml(t_html_node *node)
{
    struct s_http_response  response;
    struct s_buf            list;
    t_buf_param             *param;
    t_html_node             *resnode;
    t_html_node             *paramnode;
    char                    *ptr;
    uint                    i;

    memset(&response, 0, sizeof(struct s_http_request));
    response.header = buffer_new(sizeof(t_buf_param), 0);
    list = html_find_tag_max(node, "response", 1);
    if (list.size == 0)
        return (response);
    resnode = *((t_html_node **)buffer_get_index(&list, 0));
    if (!(ptr = buffer_param_get_var_buf_alt(&resnode->param, "version")))
        return (response);
    strncpy(response.http_version, ptr, STRING_SIZE - 1);
    if (!(ptr = buffer_param_get_var_buf_alt(&resnode->param, "code")))
        return (response);
    response.code = atoi(ptr);

    buffer_free(&list);
    list = html_find_tag_max(resnode, "header", 1);
    i = -1;
    while (++i < list.size)
    {
        paramnode = *((t_html_node **)buffer_get_index(&list, i));
        if (paramnode->param.size == 0)
            continue;
        //param = *((t_buf_param **)buffer_get_index(&paramnode->param, 0));
        param = ((t_buf_param *)buffer_get_index(&paramnode->param, 0));
        if (!(param = buffer_copy_param(param)))
        {
            http_free_response(&response);
            buffer_free(&list);
            return (response);
        }
        buffer_push(&response.header, &param);
    }
    list = html_find_tag_max(resnode, "content", 1);
    if (list.size == 0)
    {
        http_free_response(&response);
        buffer_free(&list);
        return (response);
    }
    resnode = *((t_html_node **)buffer_get_index(&list, 0));
    buffer_free(&list);
    if (strncasecmp(resnode->tag, "content", strlen("content")) != 0)
    {
        if (!(response.buf = html_tostring(resnode)))
        {
            http_free_response(&response);
            return (response);
        }
    }
    else
    {
        ptr = NULL;
        i = -1;
        while (++i < resnode->child.size)
        {
            paramnode = buffer_get_index(&resnode->child, i);
            ptr = string_stradd(ptr, html_tostring(paramnode));
        }
        response.buf = ptr;
    }
    return (response);
}

t_web_transmission          *web_transmission_import_xml(t_html_node *node)
{
    t_web_transmission      *transmission;
    struct s_buf            list;
    char                    *ptr;
    uint                    i;

    if (!node || !(transmission = ALLOC(sizeof(struct s_web_transmission))))
        return (NULL);
    memset(transmission, 0, sizeof(struct s_web_transmission));
    if (strncasecmp(node->tag, "transmission", strlen("transmission")) != 0)
    {
        list = html_find_tag_max(node, "transmission", 1);
        if (list.size == 0 || !(node = *((t_html_node **)buffer_get_index(&list, 0))))
        {
            buffer_free(&list);
            FREE(transmission);
            return (NULL);
        }
        buffer_free(&list);
    }
    if (!(ptr = buffer_param_get_var_buf_alt(&node->param, "origin")))
    {
        FREE(transmission);
        return (NULL);
    }
    transmission->origin = atoi(ptr);
    if (!(ptr = buffer_param_get_var_buf_alt(&node->param, "length")))
    {
        FREE(transmission);
        return (NULL);
    }
    transmission->length = atoi(ptr);
    if (!(ptr = buffer_param_get_var_buf_alt(&node->param, "type")))
    {
        FREE(transmission);
        return (NULL);
    }
    if (strncasecmp(ptr, "text", strlen("text")) == 0)
    {
        transmission->data = html_get_texts(node);
    }
    else if (strncasecmp(ptr, "binary", strlen("binary")) == 0)
    {
        if ((ptr = html_get_texts(node)))
        {
            ///transmission->data = string_hexdump_read(ptr);
            transmission->data = string_strdup(ptr);
            FREE(ptr);
        }
    }
    return (transmission);
}

t_web_port            *web_port_import_xml(t_html_node *node)
{
    t_web_transmission      *transmission;
    t_web_port              *port;
    struct s_buf            list;
    char                    *ptr;
    uint                    i;

    if (!node || !(port = ALLOC(sizeof(struct s_web_port))))
        return (NULL);
    memset(port, 0, sizeof(struct s_web_port));
    port->transmission = buffer_new(sizeof(t_web_transmission), 0);
    if (strncasecmp(node->tag, "port", strlen("port")) != 0)
    {
        list = html_find_tag_max(node, "port", 1);
        if (list.size == 0 || !(node = *((t_html_node **)buffer_get_index(&list, 0))))
        {
            buffer_free(&list);
            FREE(port);
            return (NULL);
        }
        buffer_free(&list);
    }
    if (!(ptr = buffer_param_get_var_buf_alt(&node->param, "number")))
    {
        FREE(port);
        return (NULL);
    }
    port->number = atoi(ptr);
    if (!(ptr = buffer_param_get_var_buf_alt(&node->param, "service")))
    {
        FREE(port);
        return (NULL);
    }
    strncpy(port->service, ptr, STRING_SIZE);
    list = html_find_tag_max(node, "transmission", 1);
    i = -1;
    while (++i < list.size)
    {
        node = *((t_html_node **)buffer_get_index(&list, i));
        transmission = web_transmission_import_xml(node);
        if (port)
            buffer_push(&port->transmission, &transmission);
    }
    buffer_free(&list);
    return (port);
}

t_web_ip            *web_ip_import_xml(t_html_node *node)
{
    t_web_port              *port;
    t_web_ip                *ip;
    struct s_buf            list;
    char                    *ptr;
    uint                    i;

    if (!node || !(ip = ALLOC(sizeof(struct s_web_ip))))
        return (NULL);
    memset(ip, 0, sizeof(struct s_web_ip));
    ip->port = buffer_new(sizeof(t_web_port), 0);
    if (strncasecmp(node->tag, "ip", strlen("ip")) != 0)
    {
        list = html_find_tag_max(node, "ip", 1);
        if (list.size == 0 || !(node = *((t_html_node **)buffer_get_index(&list, 0))))
        {
            buffer_free(&list);
            FREE(ip);
            return (NULL);
        }
        buffer_free(&list);
    }
    if (!(ptr = buffer_param_get_var_buf_alt(&node->param, "version")))
    {
        FREE(ip);
        return (NULL);
    }
    ip->version = atoi(ptr);
    if (!(ptr = buffer_param_get_var_buf_alt(&node->param, "source")))
    {
        FREE(ip);
        return (NULL);
    }
    strncpy(ip->ip, ptr, STRING_SIZE);
    list = html_find_tag_max(node, "port", 1);
    i = -1;
    while (++i < list.size)
    {
        node = *((t_html_node **)buffer_get_index(&list, i));
        port = web_port_import_xml(node);
        if (port)
            buffer_push(&ip->port, &port);
    }
    buffer_free(&list);
    return (ip);
}

t_web_host          *web_host_import_xml(t_html_node *node)
{
    t_web_host              *host;
    t_web_ip                *ip;
    struct s_buf            list;
    char                    *ptr;
    uint                    i;

    if (!node || !(host = ALLOC(sizeof(struct s_web_host))))
        return (NULL);
    memset(host, 0, sizeof(struct s_web_host));
    host->ip = buffer_new(sizeof(t_web_ip), 0);
    if (strncasecmp(node->tag, "host", strlen("host")) != 0)
    {
        list = html_find_tag_max(node, "host", 1);
        if (list.size == 0 || !(node = *((t_html_node **)buffer_get_index(&list, 0))))
        {
            buffer_free(&list);
            FREE(host);
            return (NULL);
        }
        buffer_free(&list);
    }
    if (!(ptr = buffer_param_get_var_buf_alt(&node->param, "name")))
    {
        FREE(host);
        return (NULL);
    }
    host->name = string_stradd(NULL, ptr);
    list = html_find_tag_max(node, "ip", 1);
    i = -1;
    while (++i < list.size)
    {
        node = *((t_html_node **)buffer_get_index(&list, i));
        ip = web_ip_import_xml(node);
        if (ip)
            buffer_push(&host->ip, &ip);
    }
    buffer_free(&list);
    return (host);
}

struct s_http_request   http_request_import_xml(t_html_node *node)
{
    struct s_http_request   request;
    struct s_buf            list;
    t_buf_param             *param;
    t_buf_param             *tmp;
    t_html_node             *reqnode;
    t_html_node             *paramnode;
    char                    *ptr;
    uint                    i;

    memset(&request, 0, sizeof(struct s_http_request));
    request.header = buffer_new(sizeof(t_buf_param), 0);
    request.param = buffer_new(sizeof(t_buf_param), 0);
    list = html_find_tag_max(node, "request", 1);
    if (list.size == 0)
        return (request);
    reqnode = *((t_html_node **)buffer_get_index(&list, 0));
    if (!(ptr = buffer_param_get_var_buf_alt(&reqnode->param, "method")))
        return (request);
    strncpy(request.method, ptr, STRING_SIZE - 1);
    if (!(ptr = buffer_param_get_var_buf_alt(&reqnode->param, "url")))
        return (request);
    request.url = string_strdup(ptr);
    buffer_free(&list);
    list = html_find_tag_max(reqnode, "param", 1);
    i = -1;
    while (++i < list.size)
    {
        paramnode = *((t_html_node **)buffer_get_index(&list, i));
        param = *((t_buf_param **)buffer_get_index(&paramnode->param, 0));
        if (!(param = buffer_copy_param(param)))
        {
            http_free_request(&request);
            return (request);
        }
        buffer_push(&request.param, &param);
    }
    buffer_free(&list);
    list = html_find_tag_max(reqnode, "header", 1);
    i = -1;
    while (++i < list.size)
    {
        paramnode = *((t_html_node **)buffer_get_index(&list, i));
        param = buffer_get_index(&paramnode->param, 0);
        if (!(param = buffer_copy_param(param)))
        {
            http_free_request(&request);
            return (request);
        }
        buffer_push(&request.header, &param);
    }
    return (request);
}

t_web_node              *web_import_xml_node(t_html_node *node, t_web_node *parent)
{
    t_html_node         *child;
    t_web_node          *child_web;
    t_web_node          *web;
    uint                i;

    if (!node)
        return (NULL);
    if (!(web = ALLOC(sizeof(struct s_web_node))))
        return (NULL);
    memset(web, 0, sizeof(struct s_web_node));
    web->child = buffer_new(sizeof(t_web_node), 0);
    web->parent = parent;
    web->request = http_request_import_xml(node);
    web->response = http_response_import_xml(node);
    web->host = web_host_import_xml(node);
    if (web->host)
    {
        web->host->parent = web;
    }
    web->html = html_parse(web->response.buf);
    i = -1;
    while (++i < node->child.size)
    {
        child = ((t_html_node *)buffer_get_index(&node->child, i));
        if (strncasecmp(child->tag, "web", strlen("web")) != 0)
            continue;
        if (!(child_web = web_import_xml_node(child, web)))
        {
            web_free_node(web);
            FREE(web);
            return (NULL);
        }
        buffer_push(&web->child, &child_web);
    }
    return (web);
}

t_web_node          *web_import_xml(char *xml)
{
    t_web_node             *web;
    t_html_node            *root;

    if (!xml)
        return (NULL);
    printf("Parsing XML\n");
    if (!(root = html_new_node(xml, NULL, NULL)))
        return (NULL);
    //html_display_node(root, 0); //
    printf("XML to Web node\n");
    web = web_import_xml_node(root, NULL);
    // Tarzan
    ///html_free_node(root); // Crash LEAK
    return (web);
}

t_web_node          *web_root_node(t_web_node *node)
{
    if (!node)
        return (NULL);
    while (node->parent)
        node = node->parent;
    return (node);
}

int                 web_url_exists(t_web_node *node, char *url)
{
    t_web_node      *child;
    uint            i;

    if (!node || !url)
        return (0);
    if (node->request.url && /// TEST DEBUG ??
        strncmp(node->request.url, url, strlen(url)) == 0)
        return (1);
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        if (web_url_exists(child, url))
            return (1);
    }
    return (0);
}

t_web_node          *web_new_node_nochild(char *url, t_web_node *parent)
{
    t_web_node              *node;
    t_web_node              *child;
    struct s_html_node      root;
    struct s_http_response  page;
    struct s_buf            list;
    char                    *full_url;
    t_html_node             *tag;
    t_buf_param             *param;
    uint                    i;
    uint                    j;

    if (!url)
        return (NULL);
    ///printf("Press enter to continue\n");//
    ///getchar(); //
    printf("New node URL [%s]\n", url); //
    if (!(node = ALLOC(sizeof(struct s_web_node))))
        return (NULL);
    memset(node, 0, sizeof(struct s_web_node));
    node->parent = parent;
    page = web_get_page(url, &node->request);
    if (page.code == 0)
    {
        web_free_node(node);
        return (NULL);
    }
    root = html_parse(page.buf);
    //html_display_node(&root, 0);
    node->html = root;
    node->response = page;
    node->child = buffer_new(sizeof(t_web_node), 0);
    return (node);
}

t_web_node          *web_new_node(char *url, t_web_node *parent, uint maxdepth)
{
    t_web_node              *node;
    t_web_node              *child;
    struct s_html_node      root;
    struct s_http_response  page;
    struct s_buf            list;
    char                    *full_url;
    t_html_node             *tag;
    t_buf_param             *param;
    uint                    i;
    uint                    j;

    if (!url || maxdepth == 0)
        return (NULL);
    ///printf("Press enter to continue\n");//
    ///getchar(); //
    printf("New node URL [%s]\n", url); //
    if (!(node = ALLOC(sizeof(struct s_web_node))))
        return (NULL);
    memset(node, 0, sizeof(struct s_web_node));
    node->parent = parent;
    page = web_get_page(url, &node->request);
    if (page.code == 0)
    {
        web_free_node(node);
        return (NULL);
    }
    root = html_parse(page.buf);
    node->html = root;

    node->response = page;

    if (maxdepth == 0)
        return (node);
    list = html_find_tag(&root, "a");

    node->child = buffer_new(sizeof(t_web_node), 0);
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                if (strncasecmp(param->data.buf, "mailto:", strlen("mailto:")) == 0)
                    continue;
                ///printf("HREF == [%s]\n", (char *)param->data.buf); //
                full_url = url_get_full(url, param->data.buf);
                if (web_url_exists(web_root_node(node), full_url) ||
                    web_url_exists(node, full_url))
                {
                    ///printf("Exist [%s]\n", full_url);
                    FREE(full_url);
                    continue;
                }
                child = web_new_node(full_url, node, maxdepth - 1);
                if (child)
                    buffer_push(&node->child, &child);
                FREE(full_url);
            }
        }
    }
    buffer_free(&list);
    return (node);
}

void            web_shell_display_prompt(t_web_node *node, int maxdepth)
{
    if (!node || maxdepth == 0)
        return ;
    if (maxdepth < 0)
        web_shell_display_prompt(node->parent, -1);
    else
    {
        if (maxdepth - 1 <= 0 && node->parent)
            printf("...\n");
        web_shell_display_prompt(node->parent, maxdepth - 1);
    }
    printf("%s\n", node->request.url);
}

void            web_shell_display_help(void)
{
    printf("----- HELP -----\n");
    printf("exit : Return to parent node\n");
    printf("return : Return to parent node\n");
    printf("quit : Exit shell\n");
    printf("web_get_page : Add new nodes\n");
    printf("info : Node informations\n");
    printf("request : Display request\n");
    printf("response : Display reponse\n");
    printf("child : Display childs\n");
    printf("goto : Goto child\n");
    printf("export : Export to XML\n");
    printf("import : Import XML web node\n");
    printf("save : Export everything to XML\n");
    printf("content : View raw node content\n");
    printf("texts : Display all text\n");
    printf("comments : Display all HTML comments\n");
    printf("texttag : Display text that match with a tagname\n");
    printf("htmldisplay : Display the HTML structure\n");
    printf("nodedisplay : Display the HTML node structure\n");
    printf("getword : Display words\n");
    printf("links : Display page links\n");
    printf("expand : Download all sublinks of node\n");
    printf("expandsamesite : Download all sublinks of same host of node\n");
    printf("expandnotsamesite : Download all sublinks of not the same host of node\n");
    printf("expandallsamesite : Download recursively all sublinks of not the same host of node\n");
    printf("expandallnotsamesite : Download recursively all sublinks of not the same host of node\n");
    printf("mail : Display all mails of node tree\n");
    printf("form : Display forms\n");
    printf("forminput : Display form input\n");
    printf("host : Host shell\n");
    printf("----------------\n");
}

int             web_shell_command_comments(char *input, t_web_node *node)
{
    char        *comments;

    if (!input || !node)
        return (1);
    if (!(comments = html_get_comments(&node->html)))
        return (1);
    printf("%s\n", comments);
    FREE(comments);
    return (0);
}

int                 web_shell_command_texts(char *input, t_web_node *node)
{
    char            *text;
    if (!input || !node)
        return (1);
    if (!(text = html_get_texts(&node->html)))
        return (1);
    printf("%s\n", text);
    FREE(text);
    return (0);
}

void            buffer_display_string_list(t_buf *strbuf)
{
    uint        i;
    char        *str;

    if (!strbuf)
        return ;
    i = -1;
    while (++i < strbuf->size)
        printf("[%u] [%s]\n", i, (char *)buffer_get_index(strbuf, i));
}

int             buffer_contain_string_case(t_buf *strbuf, char *string)
{
    uint        i;
    char        *str;

    if (!strbuf)
        return (-1);
    i = -1;
    while (++i < strbuf->size)
    {
        str = *((char **)buffer_get_index(strbuf, i));
        if (strncasecmp(str, string, strlen(string)) == 0)
            return (i);
    }
    return (-1);
}

int             buffer_contain_string(t_buf *strbuf, char *string)
{
    uint        i;
    char        *str;

    if (!strbuf || !string)
        return (-1);
    i = -1;
    while (++i < strbuf->size)
    {
        str = *((char **)buffer_get_index(strbuf, i));
        if (!str)
            continue;
        if (strncmp(str, string, strlen(string)) == 0)
            return (i);
    }
    return (-1);
}

int             buffer_contain_string_case_count(t_buf *strbuf, char *string)
{
    uint        i;
    uint        count;
    char        *str;

    if (!strbuf)
        return (0);
    count = 0;
    i = -1;
    while (++i < strbuf->size)
    {
        if ((str = *((char **)buffer_get_index(strbuf, i))))
            if (strncasecmp(str, string, strlen(string)) == 0)
                count++;
    }
    return (count);
}

int             buffer_contain_string_count(t_buf *strbuf, char *string)
{
    uint        i;
    uint        count;
    char        *str;

    if (!strbuf)
        return (0);
    count = 0;
    i = -1;
    while (++i < strbuf->size)
    {
        if ((str = *((char **)buffer_get_index(strbuf, i))))
            if (strncmp(str, string, strlen(string)) == 0)
                count++;
    }
    return (count);
}

char            *string_replace_noalloc(char *str, char src, char change)
{
    char        *begin;

    if (!(begin = str))
        return (NULL);
    str--;
    while (*(++str))
        if (*str == src)
            *str = change;
    return (begin);
}

struct s_buf    string_strsplit(char *str, char split)
{
    struct s_buf    list;
    char            *push;
    char            *endofstring;

    list = buffer_new(sizeof(char *), 0);
    if (!str)
        return (list);
    while (*str)
    {
        while (*str == split)
            str++;
        endofstring = str;
        while (*endofstring && *endofstring != split)
            endofstring++;
        push = string_duplicate(str, endofstring - str);
        buffer_push(&list, &push);
        str = endofstring;
    }
    return (list);
}

void            *buffer_free_string(t_buf *buf)
{
    char        *str;
    uint        i;

    if (!buf)
        return (NULL);
    i = -1;
    while (++i < buf->size)
    {
        str = *((char **)buffer_get_index(buf, i));
        FREE(str);
    }
    buffer_free(buf);
    return (NULL);
}

void            buffer_display_param_list_order(t_buf *list)
{
    uint            max;
    uint            limit;
    uint            i;
    int             value;
    t_buf_param     *param;

    if (!list)
        return ;
    limit = 0;
    max = 1;
    i = -1;
    while (++i < list->size)
    {
        param = *((t_buf_param **)buffer_get_index(list, i));
        if (atoi(param->name) > limit)
            limit = atoi(param->name);
    }
    while (max <= limit)
    {
        i = -1;
        while (++i < list->size)
        {
            param = *((t_buf_param **)buffer_get_index(list, i));
            if (atoi(param->name) == max)
                printf("[%u] %s\n", max, (char *)param->data.buf);
        }
        max++;
        // Can be optimized
    }
}

int             web_shell_command_getword(char *input, t_web_node *node)
{
    char            *word;
    char            *search;
    char            *full_text;
    struct s_buf    keywords;
    struct s_buf    printed;
    uint            i;
    uint            occurence;
    t_buf_param     *param;
    struct s_buf    paramlist;

    if (!input || !node)
        return (1);
    if (!(full_text = html_get_texts(&node->html)))
        return (1);
    search = NULL;
    printed = buffer_new(sizeof(char *), 0);
    keywords = string_strsplit(string_replace_noalloc(string_replace_noalloc(full_text, '\r', ' '), '\n', ' '), ' ');
    FREE(full_text);
    if ((word = string_goto(input, ' ')) &&
        (word = string_skipblank(word)) &&
        (word = string_strdup(word))
        )
    {
        if (!(search = string_strip(word, ' ')))
        {
            FREE(word);
            return (1);
        }
        FREE(word);
    }
    paramlist = buffer_new(sizeof(t_buf_param), 0);
    i = -1;
    while (++i < keywords.size)
    {
        if (!(word = *((char **)buffer_get_index(&keywords, i))))
            continue;
        if ((search && buffer_contain_string_case(&printed, word) != -1) ||
            (!search && buffer_contain_string(&printed, word) != -1))
            continue;
        else
        {
            if (search && strncasecmp(search, word, strlen(search)) != 0)
                continue;
            if (search)
                occurence = buffer_contain_string_case_count(&keywords, word);
            else
                occurence = buffer_contain_string_count(&keywords, word);
            if (!(param = ALLOC(sizeof(struct s_buf_param))))
                break;
            itoa(occurence, param->name, 10);
            param->data = buffer_new(1, 0);
            param->data.size = strlen(word);
            param->data.buf = string_strdup(word);
            buffer_push(&paramlist, &param);
            word = string_strdup(word);
            buffer_push(&printed, &word);
        }
    }
    if (search)
        FREE(search);
    buffer_free_string(&printed);
    buffer_free_string(&keywords);
    buffer_display_param_list_order(&paramlist);
    buffer_free_param_list(&paramlist);
}

typedef struct {
    t_web_node  *node;
    ///t_html_node *tag; ///
    char        *url;
} thread_data_t;

typedef struct {
    thread_data_t *tasks;
    int task_count;
    int task_index;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} thread_pool_t;

void *process_tag(void *arg)
{
    thread_pool_t *pool = (thread_pool_t *)arg;
    pthread_mutex_lock(&pool->mutex);

    // Attendre qu'il y ait des tâches à traiter
    while (pool->task_index >= pool->task_count) {
        pthread_cond_wait(&pool->cond, &pool->mutex);
    }

    // Récupérer la tâche
    thread_data_t data = pool->tasks[pool->task_index];
    pool->task_index++;
    pthread_mutex_unlock(&pool->mutex);

    // Vérification des pointeurs
    if (!data.node || !data.url) {
        printf("Invalid node or tag\n");
        return (NULL);
    }

    t_web_node  *node = data.node;
    //t_html_node *tag = data.tag;
    char        *url = data.url;
    char        *full_url;

    if (url && *((char *)url) == '#')
        return (NULL);
    if (strncasecmp(url, "mailto:", strlen("mailto:")) == 0)
        return (NULL);
    full_url = url_get_full(node->request.url, url);
    if (!full_url) {
        printf("Failed to get full URL\n");
        return (NULL);
    }
    if (web_url_exists(web_root_node(node), full_url) ||
        web_url_exists(node, full_url)) {
        FREE(full_url);
        return (NULL);
    }
    t_web_node *child = web_new_node_nochild(full_url, node);
    if (child) {
        pthread_mutex_lock(&node->mutex);
        buffer_push(&node->child, &child);
        pthread_mutex_unlock(&node->mutex);
    }
    FREE(full_url);
    return (NULL);
}

int web_shell_command_expand(char *input, t_web_node *node) {
    struct s_buf list;
    t_html_node *tag;
    thread_pool_t pool;

    // Vérification des entrées
    if (!node || !input)
        return (1);

    list = html_find_tag(&node->html, "a");
    /// TODO FILTER UNIQUE


    /////////////////////////////////////////////////////
    t_buf_param         *param;
    char                *full_url;
    struct s_buf        printed;
    uint                i;
    uint                j;

    printed = buffer_new(sizeof(char *), 0);
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                full_url = url_get_full(node->request.url, param->data.buf);
                if (buffer_contain_string(&printed, full_url) != -1)
                {
                    FREE(full_url);
                    continue;
                }
                buffer_push(&printed, &full_url);
            }
        }
    }
    buffer_free(&list);
    /////////////////////////////////////////////////////

    size_t num_tags = printed.size;

    // Initialiser le pool de threads
    pthread_t *threads;
    if (!(threads = ALLOC(sizeof(pthread_t) * num_tags)))
    {
        buffer_free_string(&printed);
        return (1);
    }
    pool.tasks = malloc(num_tags * sizeof(thread_data_t));
    pool.task_count = num_tags;
    pool.task_index = 0;
    pthread_mutex_init(&pool.mutex, NULL);
    pthread_cond_init(&pool.cond, NULL);

    char *url; //bugshit
    // Remplir le pool de tâches
    for (size_t i = 0; i < num_tags; i++) {
        url = *((char **)buffer_get_index(&printed, i));
        pool.tasks[i].node = node;
        pool.tasks[i].url = url;
    }

    // Créer les threads
    for (int i = 0; i < num_tags; i++) {
        pthread_create(&threads[i], NULL, process_tag, &pool);
    }

    // Signaler aux threads qu'il y a des tâches à traiter
    pthread_mutex_lock(&pool.mutex);
    pool.task_index = 0; // Réinitialiser l'index des tâches
    pthread_cond_broadcast(&pool.cond); // Signaler tous les threads
    pthread_mutex_unlock(&pool.mutex);

    // Attendre que tous les threads se terminent
    for (int i = 0; i < num_tags; i++) {
        pthread_join(threads[i], NULL);
    }

    // Libération des ressources
    free(pool.tasks);
    pthread_mutex_destroy(&pool.mutex);
    pthread_cond_destroy(&pool.cond);
    buffer_free_string(&printed);
    FREE(threads);
    return (0);
}

int             web_shell_command_expand_singlethread(char *input, t_web_node *node)
{
    t_web_node              *child;
    struct s_buf            list;
    char                    *full_url;
    t_html_node             *tag;
    t_buf_param             *param;
    uint                    i;
    uint                    j;

    // Expand
    if (!node || !input)
        return (1);
    list = html_find_tag(&node->html, "a");
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                if (strncasecmp(param->data.buf, "mailto:", strlen("mailto:")) == 0)
                    continue;
                full_url = url_get_full(node->request.url, param->data.buf);
                if (web_url_exists(web_root_node(node), full_url) ||
                    web_url_exists(node, full_url))
                {
                    FREE(full_url);
                    continue;
                }
                child = web_new_node_nochild(full_url, node);
                if (child)
                    buffer_push(&node->child, &child);
                FREE(full_url);
            }
        }
    }
    buffer_free(&list);
    return (0);
}

int             url_same_host(char *urla, char *urlb)
{
    char        *hosta;
    char        *hostb;

    if (!urla || !urlb)
        return (0);
    if (!(hosta = url_get_host(urla)))
        return (0);
    if (!(hostb = url_get_host(urlb)))
    {
        FREE(hosta);
        return (0);
    }
    if (strncasecmp(hosta, hostb, strlen(hostb)) == 0)
    {
        FREE(hosta);
        FREE(hostb);
        return (1);
    }
    FREE(hosta);
    FREE(hostb);
    return (0);
}

void *process_tag_samesite(void *arg)
{
    thread_pool_t *pool = (thread_pool_t *)arg;
    pthread_mutex_lock(&pool->mutex);

    // Attendre qu'il y ait des tâches à traiter
    while (pool->task_index >= pool->task_count) {
        pthread_cond_wait(&pool->cond, &pool->mutex);
    }

    // Récupérer la tâche
    thread_data_t data = pool->tasks[pool->task_index];
    pool->task_index++;
    pthread_mutex_unlock(&pool->mutex);

    // Vérification des pointeurs
    if (!data.node || !data.url) {
        printf("Invalid node or tag\n");
        return (NULL);
    }

    t_web_node  *node = data.node;
    //t_html_node *tag = data.tag;
    char        *url = data.url;
    char        *full_url;

    if (url && *((char *)url) == '#')
        return (NULL);
    if (strncasecmp(url, "mailto:", strlen("mailto:")) == 0)
        return (NULL);
    full_url = url_get_full(node->request.url, url);
    if (!full_url) {
        printf("Failed to get full URL\n");
        return (NULL);
    }
    if (!url_same_host(node->request.url, full_url) ||
        web_url_exists(web_root_node(node), full_url) ||
        web_url_exists(node, full_url)) {
        FREE(full_url);
        return (NULL);
    }
    t_web_node *child = web_new_node_nochild(full_url, node);
    if (child) {
        pthread_mutex_lock(&node->mutex);
        buffer_push(&node->child, &child);
        pthread_mutex_unlock(&node->mutex);
    }
    FREE(full_url);
    return (NULL);
}

void *process_tag_notsamesite(void *arg)
{
    thread_pool_t *pool = (thread_pool_t *)arg;
    pthread_mutex_lock(&pool->mutex);

    // Attendre qu'il y ait des tâches à traiter
    while (pool->task_index >= pool->task_count) {
        pthread_cond_wait(&pool->cond, &pool->mutex);
    }

    // Récupérer la tâche
    thread_data_t data = pool->tasks[pool->task_index];
    pool->task_index++;
    pthread_mutex_unlock(&pool->mutex);

    // Vérification des pointeurs
    if (!data.node || !data.url) {
        printf("Invalid node or tag\n");
        return (NULL);
    }

    t_web_node  *node = data.node;
    //t_html_node *tag = data.tag;
    char        *url = data.url;
    char        *full_url;

    if (url && *((char *)url) == '#')
        return (NULL);
    if (strncasecmp(url, "mailto:", strlen("mailto:")) == 0)
        return (NULL);
    full_url = url_get_full(node->request.url, url);
    if (!full_url) {
        printf("Failed to get full URL\n");
        return (NULL);
    }
    if (!url_same_host(node->request.url, full_url) ||
        web_url_exists(web_root_node(node), full_url) ||
        web_url_exists(node, full_url)) {
        FREE(full_url);
        return (NULL);
    }
    t_web_node *child = web_new_node_nochild(full_url, node);
    if (child) {
        pthread_mutex_lock(&node->mutex);
        buffer_push(&node->child, &child);
        pthread_mutex_unlock(&node->mutex);
    }
    FREE(full_url);
    return (NULL);
}

int             web_shell_command_expand_samesite(char *input, t_web_node *node)
{
    struct s_buf list;
    t_html_node *tag;
    thread_pool_t pool;

    // Vérification des entrées
    if (!node || !input)
        return (1);

    list = html_find_tag(&node->html, "a");
    /// TODO FILTER UNIQUE


    /////////////////////////////////////////////////////
    t_buf_param         *param;
    char                *full_url;
    struct s_buf        printed;
    uint                i;
    uint                j;

    printed = buffer_new(sizeof(char *), 0);
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                full_url = url_get_full(node->request.url, param->data.buf);
                if (buffer_contain_string(&printed, full_url) != -1)
                {
                    FREE(full_url);
                    continue;
                }
                buffer_push(&printed, &full_url);
            }
        }
    }
    buffer_free(&list);
    /////////////////////////////////////////////////////

    size_t num_tags = printed.size;

    // Initialiser le pool de threads
    pthread_t *threads;
    if (!(threads = ALLOC(sizeof(pthread_t) * num_tags)))
    {
        buffer_free_string(&printed);
        return (1);
    }
    pool.tasks = malloc(num_tags * sizeof(thread_data_t));
    pool.task_count = num_tags;
    pool.task_index = 0;
    pthread_mutex_init(&pool.mutex, NULL);
    pthread_cond_init(&pool.cond, NULL);

    char *url; //bugshit
    // Remplir le pool de tâches
    for (size_t i = 0; i < num_tags; i++) {
        url = *((char **)buffer_get_index(&printed, i));
        pool.tasks[i].node = node;
        pool.tasks[i].url = url;
    }

    // Créer les threads
    for (int i = 0; i < num_tags; i++) {
        pthread_create(&threads[i], NULL, process_tag_samesite, &pool);
    }

    // Signaler aux threads qu'il y a des tâches à traiter
    pthread_mutex_lock(&pool.mutex);
    pool.task_index = 0; // Réinitialiser l'index des tâches
    pthread_cond_broadcast(&pool.cond); // Signaler tous les threads
    pthread_mutex_unlock(&pool.mutex);

    // Attendre que tous les threads se terminent
    for (int i = 0; i < num_tags; i++) {
        pthread_join(threads[i], NULL);
    }

    // Libération des ressources
    free(pool.tasks);
    pthread_mutex_destroy(&pool.mutex);
    pthread_cond_destroy(&pool.cond);
    buffer_free_string(&printed);
    FREE(threads);
    return (0);
}

int             web_shell_command_expand_samesite_singlethread(char *input, t_web_node *node)
{
    t_web_node              *child;
    struct s_buf            list;
    char                    *full_url;
    t_html_node             *tag;
    t_buf_param             *param;
    uint                    i;
    uint                    j;

    // Expand
    if (!node || !input)
        return (1);
    list = html_find_tag(&node->html, "a");
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                if (strncasecmp(param->data.buf, "mailto:", strlen("mailto:")) == 0)
                    continue;
                full_url = url_get_full(node->request.url, param->data.buf);
                if (!url_same_host(node->request.url, full_url) ||
                    web_url_exists(web_root_node(node), full_url) ||
                    web_url_exists(node, full_url))
                {
                    FREE(full_url);
                    continue;
                }
                child = web_new_node_nochild(full_url, node);
                if (child)
                    buffer_push(&node->child, &child);
                FREE(full_url);
                if (!child)
                {
                    buffer_free(&list);
                    return (1);
                }
            }
        }
    }
    buffer_free(&list);
    return (0);
}

int             web_shell_command_mail(char *input, t_web_node *node)
{
        t_web_node              *child;
    struct s_buf            list;
    char                    *full_url;
    t_html_node             *tag;
    t_buf_param             *param;
    uint                    i;
    uint                    j;

    // Expand
    if (!node || !input)
        return (1);
    list = html_find_tag(&node->html, "a");
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                if (strncasecmp(param->data.buf, "mailto:", strlen("mailto:")) != 0)
                    continue;
                printf("%s\n", (char *)param->data.buf + strlen("mailto:"));
            }
        }
    }
    buffer_free(&list);
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        web_shell_command_mail(input, child);
    }
    return (0);
}

int             web_shell_command_expand_notsamesite(char *input, t_web_node *node)
{
    struct s_buf list;
    t_html_node *tag;
    thread_pool_t pool;

    // Vérification des entrées
    if (!node || !input)
        return (1);

    list = html_find_tag(&node->html, "a");
    /// TODO FILTER UNIQUE


    /////////////////////////////////////////////////////
    t_buf_param         *param;
    char                *full_url;
    struct s_buf        printed;
    uint                i;
    uint                j;

    printed = buffer_new(sizeof(char *), 0);
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                full_url = url_get_full(node->request.url, param->data.buf);
                if (buffer_contain_string(&printed, full_url) != -1)
                {
                    FREE(full_url);
                    continue;
                }
                buffer_push(&printed, &full_url);
            }
        }
    }
    buffer_free(&list);
    /////////////////////////////////////////////////////

    size_t num_tags = printed.size;

    // Initialiser le pool de threads
    pthread_t *threads;
    if (!(threads = ALLOC(sizeof(pthread_t) * num_tags)))
    {
        buffer_free_string(&printed);
        return (1);
    }
    pool.tasks = malloc(num_tags * sizeof(thread_data_t));
    pool.task_count = num_tags;
    pool.task_index = 0;
    pthread_mutex_init(&pool.mutex, NULL);
    pthread_cond_init(&pool.cond, NULL);

    char *url; //bugshit
    // Remplir le pool de tâches
    for (size_t i = 0; i < num_tags; i++) {
        url = *((char **)buffer_get_index(&printed, i));
        pool.tasks[i].node = node;
        pool.tasks[i].url = url;
    }

    // Créer les threads
    for (int i = 0; i < num_tags; i++) {
        pthread_create(&threads[i], NULL, process_tag_notsamesite, &pool);
    }

    // Signaler aux threads qu'il y a des tâches à traiter
    pthread_mutex_lock(&pool.mutex);
    pool.task_index = 0; // Réinitialiser l'index des tâches
    pthread_cond_broadcast(&pool.cond); // Signaler tous les threads
    pthread_mutex_unlock(&pool.mutex);

    // Attendre que tous les threads se terminent
    for (int i = 0; i < num_tags; i++) {
        pthread_join(threads[i], NULL);
    }

    // Libération des ressources
    free(pool.tasks);
    pthread_mutex_destroy(&pool.mutex);
    pthread_cond_destroy(&pool.cond);
    buffer_free_string(&printed);
    FREE(threads);
    return (0);
}
int             web_shell_command_expand_notsamesite_singlethread(char *input, t_web_node *node)
{
    t_web_node              *child;
    struct s_buf            list;
    char                    *full_url;
    t_html_node             *tag;
    t_buf_param             *param;
    uint                    i;
    uint                    j;

    // Expand
    if (!node || !input)
        return (1);
    list = html_find_tag(&node->html, "a");
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                if (strncasecmp(param->data.buf, "mailto:", strlen("mailto:")) == 0)
                    continue;
                full_url = url_get_full(node->request.url, param->data.buf);
                if (url_same_host(node->request.url, full_url) ||
                    web_url_exists(web_root_node(node), full_url) ||
                    web_url_exists(node, full_url))
                {
                    FREE(full_url);
                    continue;
                }
                child = web_new_node_nochild(full_url, node);
                if (child)
                    buffer_push(&node->child, &child);
                FREE(full_url);
                if (!child)
                {
                    buffer_free(&list);
                    return (1);
                }
            }
        }
    }
    buffer_free(&list);
    return (0);
}

int             web_expandallsamesite(t_web_node *node, uint maxdepth)
{
    uint        i;
    t_web_node  *child;

    if (!node)
        return (1);
    if (maxdepth <= 0 && maxdepth != -1)
        return (0);
    if (web_shell_command_expand_samesite("expandsamesite", node))
        return (1);
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        if (web_expandallsamesite(child, maxdepth == -1 ? -1 : maxdepth - 1))
            return (1);
    }
    return (0);
}

int             web_shell_command_expandallsamesite(char *input, t_web_node *node)
{
    char            *ptr;

    if (!input || !node)
        return (1);
    if (!(ptr = string_goto(input, ' ')))
    {
        printf("Usage: expandallsamesite <maxdepth>\n");
        return (1);
    }
    if (!(ptr = string_goto_alphanum(ptr)))
    {
        printf("Usage: expandallsamesite <maxdepth>\n");
        return (1);
    }
    web_expandallsamesite(node, atoi(ptr));
    return (0);
}

int             web_expandallnotsamesite(t_web_node *node, uint maxdepth)
{
    uint        i;
    t_web_node  *child;

    if (!node)
        return (1);
    if (maxdepth <= 0 && maxdepth != -1)
        return (0);
    if (web_shell_command_expand_notsamesite("expandnotsamesite", node))
        return (1);
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        if (web_expandallnotsamesite(child, maxdepth == -1 ? -1 : maxdepth - 1))
            return (1);
    }
    return (0);
}

int             web_shell_command_expandallnotsamesite(char *input, t_web_node *node)
{
    char            *ptr;

    if (!input || !node)
        return (1);
    if (!(ptr = string_goto(input, ' ')))
    {
        printf("Usage: expandallsamesite <maxdepth>\n");
        return (1);
    }
    if (!(ptr = string_goto_alphanum(ptr)))
    {
        printf("Usage: expandallsamesite <maxdepth>\n");
        return (1);
    }
    if (web_expandallnotsamesite(node, atoi(ptr)))
        return (1);
    return (0);
}

int             file_write(char *path, char *data, uint *length)
{
    int             fd;
    uint            size;
	mode_t		    mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    if (!path || !data)
        return (1);
    if (length)
        size = *length;
    else
        size = strlen(data);
    #ifndef _WIN32 /// Linux
    if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR, mode)) == -1) // Ecrase le fichier s'il existe
	{
		printf("Can't open %s\n", path);
		return (1);
	}
    if (write(fd, data, size) == -1)
    {
        printf("Write error.");
        close(fd);
        return (1);
    }
    close(fd);
    return (0);
    #else // Windows not implemented
    DEBUG //
    printf("file_write Windows : Not implemented.\n"); //
    return (1);
    #endif
}

int             web_shell_command_export(char *input, t_web_node *node)
{
    char        *xml;
    char        *endofstring;
    char        *filename;
    char        *ptr;

    DEBUG //
    if (!node || !input || !(xml = web_export_xml(node)))
        return (1);
    DEBUG //
    if (!(ptr = string_goto_multiple(string_goto(input, ' '), "'\"abcdefghijklmnopqrstuvwxyz")))
    {
        printf("%s\n", xml);
        FREE(xml);
        return (0);
    }
    if (*ptr == '\'' || *ptr == '"')
        filename = html_new_string(ptr, &endofstring);
    else
    {
        if ((endofstring = string_goto(ptr, ' ')))
            filename = string_duplicate(ptr, endofstring - ptr);
        else
            filename = string_strdup(ptr);
    }
    if (file_write(filename, xml, NULL))
    {
        FREE(filename);
        FREE(xml);
        printf("Failed saving XML to %s\n", filename);
        return (1);
    }
    FREE(filename);
    FREE(xml);
    return (0);
}

char            *file_read(char *path, uint *size)
{
    mode_t		        mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    int                 fd;
	uchar 				buffer[STRING_SIZE * 128];
	uint 				bytes_read;
	struct s_buf        out;
	struct s_buf        src;

	if (!path)
        return (NULL);
    printf("Opening [%s]\n", path);
	if ((fd = open(path, O_RDONLY, mode)) == -1)
	{
		printf("Can't open %s\n", path);
		return (NULL);
	}
    printf("Reading\n");
    out = buffer_new(1, 0);
	while ((bytes_read = read(fd, (void *)buffer, STRING_SIZE * 128)) != 0)
	{
	    if (bytes_read == -1)
        {
            buffer_free(&out);
            buffer_free(&src);
            close(fd);
            printf("read error\n");
            return (NULL);
        }
        src = buffer_new(1, bytes_read);
        memcpy(src.buf, buffer, bytes_read);
        buffer_concat(&out, &src);
		buffer_free(&src);
	}
	if (size)
        *size = out.size;
    return (out.buf);
}

int             web_shell_command_import(char *input, t_web_node *node)
{
    char        *xml;
    char        *endofstring;
    char        *filename;
    char        *ptr;
    t_web_node  *child;

    if (!node || !input)
        return (1);
    if (!(ptr = string_goto_multiple(string_goto(input, ' '), "'\"abcdefghijklmnopqrstuvwxyz")))
    {
        printf("Usage: <file>\n");
        return (1);
    }
    if (*ptr == '\'' || *ptr == '"')
        filename = html_new_string(ptr, &endofstring);
    else
    {
        if ((endofstring = string_goto(ptr, ' ')))
            filename = string_duplicate(ptr, endofstring - ptr);
        else
            filename = string_strdup(ptr);
    }
    if (!(xml = file_read(filename, NULL)))
    {
        printf("Failed loading XML %s\n", filename);
        FREE(xml);
        FREE(filename);
        return (1);
    }
    FREE(filename);
    printf("Import XML\n");
    if (!(child = web_import_xml(xml)))
    {
        printf("Failed import XML structure.\n");
        FREE(xml);
        return (1);
    }
    child->parent = node;
    FREE(xml);
    if (buffer_push(&node->child, &child))
    {
        printf("Error adding child.\n");
        web_free_node(child);
        FREE(child);
        return (1);
    }
    return (0);
}

int             web_shell_command_web_get_page(char *input, t_web_node **rootnode)
{
    char        *url;
    char        *ptr;
    char        *endofstring;
    t_web_node  *child;
    t_web_node  *node;

    if (!rootnode)
        return (1);
    node = *rootnode;
    if (!input)
        return (1);
    if (!(ptr = string_goto_multiple(string_goto(input, ' '), "'\"abcdefghijklmnopqrstuvwxyz")))
    {
        printf("Usage: web_get_page <url> <depth>\n");
        return (1);
    }
    if (*ptr == '\'' || *ptr == '"')
        url = html_new_string(ptr, &endofstring);
    else
    {
        if ((endofstring = string_goto(ptr, ' ')))
            url = string_duplicate(ptr, endofstring - ptr);
        else
        {
            printf("Usage: web_get_page <url> <depth>\n");
            return (1);
        }
    }
    if (*endofstring == '\'' || *endofstring == '"')
        endofstring++;
    if (!(ptr = string_skipblank(endofstring)))
    {
        printf("Usage: web_get_page <url> <depth>\n");
        return (1);
    }
    if (ptr && is_numeric(*ptr))
    {
        if ((child = web_new_node(url, node, atoi(ptr))))
        {
            if (!node)
                *rootnode = child;
            else if (buffer_push(&node->child, &child))
                printf("Error pushing new child.\n");
        }
    }
    return (0);
}

int             web_shell_command_links(char *input, t_web_node *node)
{
    struct s_buf        list;
    t_buf_param         *param;
    char                *full_url;
    t_html_node         *tag;
    char                *text;
    uint                i;
    uint                j;
    struct s_buf        printed;

    if (!node || !input)
        return (1);
    printed = buffer_new(sizeof(char *), 0);
    list = html_find_tag(&node->html, "a");
    i = -1;
    while (++i < list.size)
    {
        tag = *((t_html_node **)buffer_get_index(&list, i));
        j = -1;
        while (++j < tag->param.size)
        {
            param = buffer_get_index(&tag->param, j);
            if (strncasecmp(param->name, "href", STRING_SIZE) == 0)
            {
                if (param->data.buf && *((char *)param->data.buf) == '#')
                    continue;
                full_url = url_get_full(node->request.url, param->data.buf);
                if (buffer_contain_string(&printed, full_url) != -1)
                {
                    FREE(full_url);
                    continue;
                }
                buffer_push(&printed, &full_url);
                text = html_get_texts(tag);
                printf("%s\n%s\n-------------------------\n", text, full_url);
                FREE(text);
            }
        }
    }
    printf("Total links: %u\n", printed.size);
    buffer_free(&list);
    buffer_free_string(&printed);
    return (0);
}

int             web_shell_command_delete(char *input, t_web_node *node)
{
    t_web_node      *child;
    char            *ptr;
    int             i;

    if (!input || !node)
        return (0);
    if ((ptr = string_goto_numeric(input)))
    {
        i = atoi(ptr);
        if (i >= 0 && i < node->child.size)
        {
            child = *((t_web_node **)buffer_get_index(&node->child, (uint)i));
            if (!child)
                printf("Bad child index\n");
            ///web_free_node(child); // LEAKS
            buffer_delete_index(&node->child, i);
        }
        else
            printf("Bad child index\n");
    }
    else
        printf("Usage: goto [index]\n");
    return (0);
}

int             web_shell(t_web_node *node);
int             web_shell_command_goto(char *input, t_web_node *node)
{
    t_web_node      *child;
    char            *ptr;
    int             i;

    if (!input || !node)
        return (0);
    if ((ptr = string_goto_numeric(input)))
    {
        i = atoi(ptr);
        if (i < node->child.size)
        {
            child = *((t_web_node **)buffer_get_index(&node->child, (uint)i));
            if (!child)
                printf("Bad child index\n");
            else if (web_shell(child))
                return (1);
        }
        else
            printf("Bad child index\n");
    }
    else
        printf("Usage: goto [index]\n");
    return (0);
}

char                  *web_port_get_service(uint port)
{
    if (port == 21)
        return (string_strdup("FTP"));
    if (port == 22)
        return (string_strdup("SSH"));
    if (port == 25)
        return (string_strdup("SMTP"));
    if (port == 80)
        return (string_strdup("HTTP"));
    if (port == 443)
        return (string_strdup("HTTPS"));
    if (port == 3306)
        return (string_strdup("MySQL"));
    return (string_strdup("Telnet"));
}

int             web_display_ip(t_web_ip *ip)
{
    t_web_port  *port;
    uint        i;

    if (!ip)
        return (1);
    printf("---------------\n");
    printf("\tIP [%s]\n", ip->ip);
    printf("\tVersion [%d]\n", ip->version);
    printf("\tOpen ports [%d]\n", ip->port.size);
    if (ip->port.size == 0)
        return (0);
    printf("\tServices: ");
    i = -1;
    while (++i < ip->port.size)
    {
        port = *((t_web_port **)buffer_get_index(&ip->port, i));
        printf("[%u](%d)%s", i, port->number, port->service);
        if (i + 1 < ip->port.size)
            printf(", ");
    }
    printf("\n");
    return (0);
}

int             web_display_host(t_web_host *host)
{
    uint        i;
    char        *hostname;
    t_web_ip    *ip;

    if (!host)
        return (1);
    if (host->name)
        printf("Hostname : %s\n", host->name);
    i = -1;
    while (++i < host->ip.size)
    {
        ip = *((t_web_ip **)buffer_get_index(&host->ip, i));
        if (!ip)
            continue;
        printf("%u ", i);
        web_display_ip(ip);
    }
    return (0);
}

t_web_transmission      *web_new_transmission(uint origin, char *data, uint length)
{
    t_web_transmission  *transmission;

    if (!data || length == 0)
        return (NULL);
    if (!(transmission = ALLOC(sizeof(struct s_web_transmission))))
        return (NULL);
    memset(transmission, 0, sizeof(struct s_web_transmission));
    if (!(transmission->data = ALLOC(length + 1)))
    {
        FREE(transmission);
        return (NULL);
    }
    memset(transmission->data, 0, length + 1);
    memcpy(transmission->data, data, length);
    transmission->length = length;
    return (transmission);
}

t_web_port            *web_new_port(uint number)
{
    t_web_port          *port;
    char                *service;

    if (!(port = ALLOC(sizeof(struct s_web_port))))
        return (NULL);
    memset(port, 0, sizeof(struct s_web_port));
    port->transmission = buffer_new(sizeof(t_web_transmission), 0);
    port->number = number;
    if (!(service = web_port_get_service(number)))
    {
        FREE(port);
        return (NULL);
    }
    strncpy(port->service, service, STRING_SIZE);
    FREE(service);
    /// scan port exchange
    return (port);
}

t_web_ip            *web_new_ip(t_web_host *host, char *ipaddr)
{
    t_web_ip        *ip;

    if (!host || !ipaddr)
        return (NULL);
    if (!(ip = ALLOC(sizeof(struct s_web_ip))))
        return (NULL);
    memset(ip, 0, sizeof(struct s_web_ip));
    ip->port = buffer_new(sizeof(t_web_port), 0);
    strncpy(ip->ip, ipaddr, STRING_SIZE);
    if (url_is_ipv4(ipaddr))
        ip->version = 4;
    else if (url_is_ipv6(ipaddr))
        ip->version = 6;
    return (ip);
}

t_web_host          *web_new_host(t_web_node *parent)
{
    struct addrinfo     hints, *res, *p;
    char                ipstr[INET6_ADDRSTRLEN];
    char                *hostname;
    t_web_host          *host;
    t_web_ip            *ip;

    if (!parent)
        return (NULL);
    if (!(host = ALLOC(sizeof(struct s_web_host))))
        return (NULL);
    memset(host, 0, sizeof(struct s_web_host));
    host->ip = buffer_new(sizeof(t_web_ip), 0);
    host->parent = parent;
    if (!(hostname = url_get_host(parent->request.url)))
    {
        FREE(host);
        return (NULL);
    }
    host->name = hostname;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // IPv4 ou IPv6
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(status));
        web_free_host(host);
        FREE(host);
        return (NULL);
    }

    printf("Adresses IP pour %s:\n", hostname);
    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        // Vérifie si c'est une adresse IPv4 ou IPv6
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        // Convertit l'adresse IP en chaîne de caractères
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("  %s\n", ipstr);
        if (!(ip = web_new_ip(host, ipstr)))
        {
            freeaddrinfo(res);
            web_free_host(host);
            FREE(host);
            return (NULL);
        }
        if (buffer_push(&host->ip, &ip))
        {
            if (ip)
            {
                web_free_ip(ip);
                FREE(ip);
            }
            freeaddrinfo(res);
            web_free_host(host);
            FREE(host);
            return (NULL);
        }
    }
    freeaddrinfo(res); // Libère la mémoire allouée par getaddrinfo
    return (host);
}

void            web_shell_host_display_help(void)
{
    printf("----- HELP -----\n");
    printf("exit : Return to parent node\n");
    printf("return : Return to parent node\n");
    printf("quit : Exit shell\n");
    printf("info : Host informations\n");
    printf("goto : Goto ip\n");
    printf("----------------\n");
}

void            web_shell_host_display_prompt(t_web_host *host)
{
    char            *hostname;

    if (!host || !host->parent)
        return ;
    hostname = url_get_host(host->parent->request.url);
    printf("%s\n", hostname);
    FREE(hostname);
}

void            web_display_transmission(t_web_transmission *trans)
{
    if (!trans)
        return ;
    printf("---------------\n");
    if (trans->origin == 0)
        printf("RECV:");
    else
        printf("SEND:");
    printf("%u\n", trans->length);
    debug_string(trans->data, trans->length);
}

void            web_shell_port_display_help(void)
{
    printf("----- HELP -----\n");
    printf("exit : Return to parent node\n");
    printf("return : Return to parent node\n");
    printf("quit : Exit shell\n");
    printf("info : Port informations\n");
    printf("----------------\n");
}

void            web_display_port(t_web_port *port)
{
    uint                    i;
    t_web_transmission      *trans;
    if (!port)
        return ;
    printf("Port: %u\n", port->number);
    printf("Service: %s\n", port->service);
    printf("Transmission:\n");
    i = -1;
    while (++i < port->transmission.size)
    {
        trans = *((t_web_transmission **)buffer_get_index(&port->transmission, i));
        if (!trans)
            continue;
        web_display_transmission(trans);
    }
}

void            web_shell_port_display_prompt(t_web_port *port, char *ip)
{
    char            *hostname;

    if (!port || !ip)
        return ;
    printf("%s:%u - [%s]\n", ip, port->number, port->service);
}

int             web_shell_port(t_web_port *port, char *ip, int ipversion)
{
    char            input[STRING_SIZE * 16]; // Pointeur pour la chaîne de caractères
    size_t          len;
    uint            i;

    if (!port)
        return (0);
    memset(input, 0, STRING_SIZE * 16);
    input[0] = 'a';
    while (strncmp(input, "exit", strlen("exit")) != 0 && strncmp(input, "return", strlen("return")) != 0)
    {
        web_shell_port_display_prompt(port, ip);
        printf(">");
        if (fgets(input, sizeof(input), stdin) != NULL)
        {
            len = strlen(input);
            if (len > 0 && input[len - 1] == '\n')
                input[len - 1] = '\0';
        }
        else
            return (1);
        if (strlen(input) == 0)
            continue;
        if (strncmp(input, "quit", strlen("quit")) == 0)
            return (1);
        if (strncmp(input, "help", strlen("help")) == 0)
            web_shell_port_display_help();
        if (strncmp(input, "info", strlen("info")) == 0)
            web_display_port(port);
    }
    return (0);
}

void            web_shell_ip_display_prompt(t_web_ip *ip)
{
    if (!ip)
        return ;
    printf("%s\n", ip->ip);
}

void            web_shell_ip_display_help(void)
{
    printf("----- HELP -----\n");
    printf("exit : Return to host\n");
    printf("return : Return to host\n");
    printf("quit : Exit shell\n");
    printf("info : IP informations\n");
    printf("scan : Scan ports\n");
    printf("goto : Goto protocol\n");
    printf("----------------\n");
}

int             web_shell_ip_command_goto(char *input, t_web_ip *ip)
{
    t_web_port      *port;
    char            *ptr;
    int             i;

    if (!input || !ip)
        return (0);
    if ((ptr = string_goto_numeric(input)))
    {
        i = atoi(ptr);
        if (i < ip->port.size)
        {
            port = *((t_web_port **)buffer_get_index(&ip->port, (uint)i));
            if (!port)
                printf("Bad port index\n");
            else if (web_shell_port(port, ip->ip, ip->version))
                return (1);
        }
        else
            printf("Bad port index\n");
    }
    else
        printf("Usage: goto [index]\n");
    return (0);
}

#include <netinet/ip6.h> // Pour struct ip6_hdr
#include <netinet/ip.h>  // Pour struct iphdr
#include <netinet/tcp.h> // Pour struct tcphdr

unsigned short ComputeChecksum(unsigned char *data, int len)
{
    unsigned long sum = 0;  /* assume 32 bit long, 16 bit short */
    unsigned short *temp = (unsigned short *)data;

    while(len > 1)
    {
        sum += *temp++;
        if(sum & 0x80000000)   // if high order bit set, fold
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
    if(len)       /* take care of left over byte */
        sum += (unsigned short) *((unsigned char *)temp);
    while(sum>>16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum;
    return sum;
}

// Fonction pour ajouter des options TCP
uint add_tcp_options(uint8_t *options) {
    uint i;

    i = -1;
    // Exemple d'ajout de l'option Maximum Segment Size (MSS)
    options[++i] = 2; // Type d'option MSS
    options[++i] = 4; // Longueur de l'option (4 octets)
    options[++i] = 0x05; // MSS (0x05B4 = 1460)
    options[++i] = 0xB4; // MSS (0x05B4 = 1460)

    // Exemple d'ajout de l'option Window Scale
    options[++i] = 4;//3; // Type d'option Window Scale
    options[++i] = 2;//3; // Longueur de l'option (3 octets)
    options[++i] = 8;//7; // Facteur de mise à l'échelle (0x07)

    options[++i] = 0x0a;
    options[++i] = 0x19;
    options[++i] = 0x27;
    options[++i] = 0x91;
    options[++i] = 0xe6;
    options[++i] = 0x00;
    options[++i] = 0x00;
    options[++i] = 0x00;
    options[++i] = 0x00;
    options[++i] = 0x01;
    options[++i] = 0x03;
    options[++i] = 0x03;
    options[++i] = 0x07;
    return (++i);
}

// Structure du pseudo-en-tête TCP
struct pseudo_header {
    uint32_t source_address;  // Adresse IP source
    uint32_t dest_address;    // Adresse IP destination
    uint8_t placeholder;       // Zéro
    uint8_t protocol;         // Protocole (TCP = 6)
    uint16_t tcp_length;      // Longueur de l'en-tête TCP + données
};

#include <time.h>

uint            net_find_valid_port(void)
{
    int sockfd;
    struct sockaddr_in server_addr;
    int port;

    // Créer un socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return (-1);
    }

    // Initialiser la structure sockaddr_in
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Accepter les connexions sur toutes les interfaces

    //port = (short)(rand() % ((SHRT_MAX + 1) - PORT_MIN)) + PORT_MIN;
    // Essayer de lier à un port valide
    for (port = (short)(rand() % ((SHRT_MAX + 1) - PORT_MIN)) + PORT_MIN; port <= PORT_MAX; port++) {
        server_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            close(sockfd);
            return (port);
        } else if (errno != EADDRINUSE) {
            close(sockfd);
            return (-1);
        }
    }

    if (port > PORT_MAX) {
        close(sockfd);
        return (-1);
    }
    close(sockfd);
    return (-1);
}

// Fonction pour construire un paquet TCP SYN
uint create_syn_packet(char *packet, void *dest, int port, int src_port, int ipversion, struct in_addr dest_ip, struct in_addr src_ip) {
    if (ipversion == 4) {
        struct tcphdr *tcp_header = (struct tcphdr *)packet;
        struct sockaddr_in *dest_4 = (struct sockaddr_in *)dest;

        // Remplir l'en-tête TCP
        memset(tcp_header, 0, sizeof(struct tcphdr));
        ///memcpy(tcp_header, tcp_syn, sizeof(struct tcphdr));
        tcp_header->source = htons(src_port);
        tcp_header->dest = htons(port);
        tcp_header->seq = 3093775308;
        tcp_header->ack_seq = 0;
        tcp_header->doff = 5; // 5 * 4 = 20 octets
        tcp_header->syn = 1;
        tcp_header->window = htons(64240);

        uint optionlen;
        optionlen = add_tcp_options(packet + sizeof(struct tcphdr));
        tcp_header->doff += (optionlen + 3) / 4;

        // Calculer la somme de contrôle
        tcp_header->check = 0;
        // Remplir le pseudo-en-tête
        struct pseudo_header psh;
        memcpy(&psh.source_address, &src_ip, sizeof(struct in_addr));
        memcpy(&psh.dest_address, &dest_ip, sizeof(struct in_addr));
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + optionlen);

        // Calculer la somme de contrôle
        int psize;
        psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + optionlen;
        char *pseudogram = ALLOC(psize);

        // Copier le pseudo-en-tête et l'en-tête TCP dans le tampon
        memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
        //memcpy(pseudogram + sizeof(struct pseudo_header), (char *)tcp_header, sizeof(struct tcphdr) + optionlen);
        memcpy(pseudogram + sizeof(struct pseudo_header), (char *)packet, sizeof(struct tcphdr) + optionlen);
        // Calculer la somme de contrôle et l'insérer dans l'en-tête TCP
        tcp_header->check = ComputeChecksum((unsigned char *)pseudogram, psize);

        // Libérer la mémoire allouée
        FREE(pseudogram);
        return (optionlen);

    } else if (ipversion == 6) {
        struct tcphdr *tcp_header = (struct tcphdr *)packet;
        struct sockaddr_in6 *dest_6 = (struct sockaddr_in6 *)dest;

        // Remplir l'en-tête TCP
        memset(tcp_header, 0, sizeof(struct tcphdr));
        tcp_header->source = htons(12345);
        tcp_header->dest = htons(port);
        tcp_header->seq = 0;
        tcp_header->ack_seq = 0;
        tcp_header->doff = 5; // 5 * 4 = 20 octets
        tcp_header->syn = 1;
        tcp_header->window = htons(5840);

        // Calculer la somme de contrôle
        ///tcp_header->check = tcp_checksum_ipv6(ip_header, tcp_header);
        return (0);
    }
}

#include <ifaddrs.h>
#include <net/if.h>

char        *net_getsourceip(void)
{
    struct ifaddrs *ifaddr, *ifa;
    char ip_str[INET6_ADDRSTRLEN]; // Pour stocker l'adresse IP sous forme de chaîne

    // Obtenir la liste des interfaces réseau
    if (getifaddrs(&ifaddr) == -1) {
        printf("getifaddrs");
        return (NULL);
    }

    // Parcourir les interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // Vérifier si l'interface a une adresse
        if (ifa->ifa_addr) {
            // Vérifier si l'interface est active
            if (ifa->ifa_flags & IFF_UP) {
                // Vérifier si l'interface est IPv4
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    // Convertir l'adresse IP en chaîne
                    if (inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip_str, sizeof(ip_str)) != NULL) {
                        if (strncasecmp(ifa->ifa_name,
                                        #ifdef _WIN32
                                        "lo", strlen("lo"))
                                        #else
                                        "lo", strlen("lo"))
                                        #endif
                                        == 0
                            )
                            continue;
                        //0printf("Interface: %s, IPv4 Address: %s\n", ifa->ifa_name, ip_str);
                        freeifaddrs(ifaddr);
                        return (string_strdup(ip_str));
                    } else {
                        printf("inet_ntop\n");
                    }
                }
                // Vérifier si l'interface est IPv6
                else if (ifa->ifa_addr->sa_family == AF_INET6) {
                    // Convertir l'adresse IP en chaîne
                    if (inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, ip_str, sizeof(ip_str)) != NULL) {
                        if (strncasecmp(ifa->ifa_name,
                                        #ifdef _WIN32
                                        "lo", strlen("lo"))
                                        #else
                                        "lo", strlen("lo"))
                                        #endif
                                        == 0
                            )
                            continue;
                        //printf("Interface: %s, IPv6 Address: %s\n", ifa->ifa_name, ip_str);
                        freeifaddrs(ifaddr);
                        return (string_strdup(ip_str));
                    } else {
                        printf("inet_ntop\n");
                    }
                }
            }
        }
    }
    // Libérer la mémoire allouée par getifaddrs
    freeifaddrs(ifaddr);
    return (NULL);
}

// Fonction pour scanner un port
int         scan_port(void *dest, char *ipdest, int port, int src_port, int ipversion)
{
    int                 sock;
    char                packet[4096];
    struct sockaddr_in  from;
    socklen_t           from_len = sizeof(from);
    int                 received;

    // Créer un socket brut
    if (ipversion == 4)
    {
        if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
            printf("Error socket\n");
            return (0);
        }
    }
    else if (ipversion == 6)
    {
        if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)) < 0) {
            printf("Error socket\n");
            return (0);
        }
    }
    else
        sock = -1;

    // Définir le timeout pour la réception
    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // Obtenir l'adresse IP source
    char *source_ip;
    struct in_addr src_ip, dest_ip;

    source_ip = net_getsourceip();
    if (ipversion == 4)
    {
        // Convertir la chaîne en in_addr
        if (inet_pton(AF_INET, source_ip, &src_ip) <= 0) {
            printf("inet_pton failed\n");
            return (0);
        }
    }
    else if (ipversion == 6)
    {
        ; /// TODO
    }
    FREE(source_ip);

    if (ipversion == 4)
    {
        // Convertir la chaîne en in_addr
        if (inet_pton(AF_INET, ipdest, &dest_ip) <= 0) {
            printf("inet_pton failed\n");
            return (0);
        }
    }
    else if (ipversion == 6)
    {
        ; /// TODO
    }

    uint option_len;

    // Envoyer le paquet SYN
    if (ipversion == 4) {
        // Créer le paquet SYN
        option_len = create_syn_packet(packet, dest, port, src_port, ipversion, dest_ip, src_ip);
        if (sendto(sock, packet, sizeof(struct tcphdr) + option_len, 0, (struct sockaddr *)dest, sizeof(struct sockaddr_in)) < 0) {
            printf("Sendto error\n");
            close(sock);
            return (0);
        }
    } else if (ipversion == 6) {
        if (sendto(sock, packet, sizeof(struct tcphdr) + option_len, 0, (struct sockaddr *)dest, sizeof(struct sockaddr_in6)) < 0) {
            printf("Sendto error\n");
            close(sock);
            return (0);
        }
    }

    // Attendre une réponse
    uint k;
    k = -1;
    while ((received = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&from, &from_len)) >= 0)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
        if (ntohs(tcp_header->source) == port)
        {
            if (tcp_header->syn == 1 && tcp_header->ack == 1) {
                //printf("OPEN\n"); //
                close(sock);
                return (1);
            } else if (tcp_header->rst == 1) {
                close(sock);
                return (0);
            }
        }
    }
    close(sock);
    return (0);
}

int             web_port_exists(t_buf *portlist, t_web_port *port)
{
    uint            i;
    t_web_port      *p;

    if (!portlist || !port)
        return (0);
    i = -1;
    while (++i < portlist->size)
    {
        p = *((t_web_port **)buffer_get_index(portlist, i));
        if (!p)
            continue;
        if (p->number == port->number)
            return (1);
    }
    return (0);
}

typedef struct s_scan_args
{
    uint                port;
    struct sockaddr_in  dest;
    char                *ipdest;
    struct sockaddr_in  source;
    int                 ipversion;
    int                 open;
    int                 thread_index;
}               t_scan_args;

void *net_thread_scan_port(void *args) {
    t_scan_args     *scan_args = (t_scan_args *)args;
    int result;
    #define SOURCE_PORT     27890

    result = scan_port(&scan_args->dest, scan_args->ipdest, scan_args->port, SOURCE_PORT + scan_args->thread_index, scan_args->ipversion);
    scan_args->open = 0;
    if (result == 1) {
        printf("Port %d open\n", scan_args->port);
        scan_args->open = result;
    }
    return (NULL);
}

int             web_shell_ip_command_scan(char *input, t_web_ip *ip)
{
    struct sockaddr_in  dest;
    t_web_port          *port;

    if (!input || !ip)
        return (1);
    memset(&dest, 0, sizeof(dest));
    dest.sin_port = htons(0); // Port non utilisé ici
    if (ip->version == 4)
    {
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, ip->ip, &dest.sin_addr); // Tarzan
    }
    else if (ip->version == 6)
    {
        dest.sin_family = AF_INET6;
        inet_pton(AF_INET6, ip->ip, &dest.sin_addr); // Tarzan
    }

    ////////////////////////////////////////////
    pthread_t threads[THREAD_COUNT];
    //struct s_web_port scan_args[THREAD_COUNT];
    struct s_scan_args  scan_args[THREAD_COUNT + 5];
    memset(scan_args, 0, sizeof(struct s_scan_args) * THREAD_COUNT);

    for (int portnumber = 1; portnumber <= PORT_MAX; portnumber++)
    {
        scan_args[(portnumber - 1) % THREAD_COUNT].port = portnumber;
        scan_args[(portnumber - 1) % THREAD_COUNT].dest = dest;
        scan_args[(portnumber - 1) % THREAD_COUNT].ipversion = ip->version;
        scan_args[(portnumber - 1) % THREAD_COUNT].ipdest = (char *)&ip->ip;
        scan_args[(portnumber - 1) % THREAD_COUNT].thread_index = (portnumber - 1) % THREAD_COUNT;
        scan_args[(portnumber - 1) % THREAD_COUNT].open = 0;

        // Créer un thread pour scanner le port
        if (pthread_create(&threads[(portnumber - 1) % THREAD_COUNT], NULL, net_thread_scan_port, &scan_args[(portnumber - 1) % THREAD_COUNT]) != 0) {
            printf("Erreur lors de la création du thread\n");
        }

        if (portnumber % 1500 == 0)
            printf("Testing ports %d...\n", portnumber); //
        // Attendre que le thread se termine si nous avons atteint le nombre maximum de threads
        if (portnumber % THREAD_COUNT == 0) {
            for (int i = 0; i < THREAD_COUNT; i++) {
                pthread_join(threads[i], NULL);
                if (scan_args[i].open == 0)
                    continue;
                if (!(port = web_new_port(scan_args[i].port)))
                {
                    printf("Error skipping %u\n", i);
                    continue;
                }
                if (web_port_exists(&ip->port, port))
                {
                    web_free_port(port);
                    FREE(port);
                    continue;
                }
                if (buffer_push(&ip->port, &port))
                {
                    printf("Error skipping %u\n", i);
                    web_free_port(port);
                    FREE(port);
                    continue;
                }
            }
            memset(scan_args, 0, sizeof(struct s_scan_args) * THREAD_COUNT);
        }
    }

    // Attendre les threads restants
    for (int i = 0; i < PORT_MAX % THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
        if (scan_args[(i - 1) % THREAD_COUNT].open != 1)
            continue;
        if (!(port = web_new_port(scan_args[(i - 1) % THREAD_COUNT].port)))
        {
            printf("Error skipping %u\n", i);
            continue;
        }
        if (web_port_exists(&ip->port, port))
        {
            web_free_port(port);
            FREE(port);
            continue;
        }
        if (buffer_push(&ip->port, &port))
        {
            printf("Error skipping %u\n", i);
            web_free_port(port);
            FREE(port);
            continue;
        }
    }
    ////////////////////////////////////////////
    /*
    for (int portnumber = 1; portnumber <= MAX_PORT; portnumber++) {
        if (scan_port(&dest, portnumber, ip->version))
        {
            if (!(port = web_new_port(portnumber)))
            {
                printf("Error skipping %u\n", portnumber);
                continue;
            }
            if (web_port_exists(&ip->port, port))
            {
                web_free_port(port);
                FREE(port);
                continue;
            }
            if (buffer_push(&ip->port, &port))
            {
                printf("Error skipping %u\n", portnumber);
                web_free_port(port);
                FREE(port);
                continue;
            }
        }
    }
    return (0);
    */
}

int             web_shell_ip(t_web_ip *ip)
{
    char            input[STRING_SIZE * 16]; // Pointeur pour la chaîne de caractères
    size_t          len;
    uint            i;

    if (!ip)
        return (0);
    memset(input, 0, STRING_SIZE * 16);
    input[0] = 'a';
    while (strncmp(input, "exit", strlen("exit")) != 0 && strncmp(input, "return", strlen("return")) != 0)
    {
        web_shell_ip_display_prompt(ip);
        printf(">");
        if (fgets(input, sizeof(input), stdin) != NULL)
        {
            len = strlen(input);
            if (len > 0 && input[len - 1] == '\n')
                input[len - 1] = '\0';
        }
        else
            return (1);
        if (strlen(input) == 0)
            continue;
        if (strncmp(input, "quit", strlen("quit")) == 0)
            return (1);
        if (strncmp(input, "help", strlen("help")) == 0)
            web_shell_ip_display_help();
        if (strncmp(input, "info", strlen("info")) == 0)
            web_display_ip(ip);
        if (strncmp(input, "scan", strlen("scan")) == 0)
            web_shell_ip_command_scan(input, ip);
        if (strncmp(input, "goto", strlen("goto")) == 0)
            if (web_shell_ip_command_goto(input, ip))
                return (1);
    }
    return (0);
}

int             web_shell_host_command_goto(char *input, t_web_host *host)
{
    t_web_ip        *ip;
    char            *ptr;
    int             i;

    if (!input || !host)
        return (0);
    if ((ptr = string_goto_numeric(input)))
    {
        i = atoi(ptr);
        if (i < host->ip.size)
        {
            ip = *((t_web_ip **)buffer_get_index(&host->ip, (uint)i));
            if (!ip)
                printf("Bad ip index\n");
            else if (web_shell_ip(ip))
                return (1);
        }
        else
            printf("Bad ip index\n");
    }
    else
        printf("Usage: goto [index]\n");
    return (0);
}

int             web_shell_host(t_web_host *host)
{
    char            input[STRING_SIZE * 16]; // Pointeur pour la chaîne de caractères
    size_t          len;
    uint            i;

    if (!host)
        return (0);
    memset(input, 0, STRING_SIZE * 16);
    input[0] = 'a';
    while (strncmp(input, "exit", strlen("exit")) != 0 && strncmp(input, "return", strlen("return")) != 0)
    {
        web_shell_host_display_prompt(host);
        printf(">");
        if (fgets(input, sizeof(input), stdin) != NULL)
        {
            len = strlen(input);
            if (len > 0 && input[len - 1] == '\n')
                input[len - 1] = '\0';
        }
        else
            return (1);
        if (strlen(input) == 0)
            continue;
        if (strncmp(input, "quit", strlen("quit")) == 0)
            return (1);
        if (strncmp(input, "help", strlen("help")) == 0)
            web_shell_host_display_help();
        if (strncmp(input, "info", strlen("info")) == 0)
            web_display_host(host);
        if (strncmp(input, "goto", strlen("goto")) == 0)
            if (web_shell_host_command_goto(input, host))
                return (1);
    }
    return (0);
}

t_web_host          *web_find_host(t_web_node *node, char *domain)
{
    uint            i;
    char            *nodedomain;
    t_web_node      *child;
    t_web_host      *ret;

    if (!node || !domain)
        return (NULL);
    if ((nodedomain = url_get_domain(node->request.url)))
    {
        if (strncasecmp(nodedomain, domain, strlen(domain)) == 0)
            if (node->host)
                return (node->host);
        FREE(nodedomain);
    }
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        if (!child)
            continue;
        if ((ret = web_find_host(child, domain)))
            return (ret);
    }
    return (NULL);
}

int             web_shell_command_host(char *input, t_web_node *node)
{
    t_web_host *host;

    if (!node || !input)
        return (0);
    if (node->host)
    {
        if (web_shell_host(node->host))
        {
            if (!node->parent)
                web_shell_command_export("export default.xml", node);
            return (1);
        }
    }
    else
    {
        char *domain;
        domain = url_get_domain(node->request.url);
        if ((host = web_find_host(web_root_node(node), domain)))
        {
            if (web_shell_host(host))
            {
                if (!node->parent)
                    web_shell_command_export("export default.xml", node);
                return (1);
            }
        }
        else if ((host = web_new_host(node)))
        {
            node->host = host;
            if (web_shell_host(host))
            {
                if (!node->parent)
                    web_shell_command_export("export default.xml", node);
                return (1);
            }
        }
        if (domain)
            FREE(domain);
    }
    return (0);
}

int             web_shell_command_texttag(char *input, t_web_node *node)
{
    char                *text;
    char                *tagname;

    if (!input || !node)
        return (0);
    tagname = input;
    while (*tagname && *tagname != ' ')
        tagname++;
    tagname = string_skipblank(tagname);
    if ((text = html_get_text_tag(&node->html, tagname)))
    {
        printf("%s\n", text);
        FREE(text);
    }
    return (0);
}

int             web_shell_command_form(char *input, t_web_node *node)
{
    uint        i;

    if (!input || !node)
        return (0);
    struct s_buf    array;
    array = html_find_tag(&node->html, "form");
    i = -1;
    while (++i < array.size)
    {
        t_html_node     *node;

        node = *((t_html_node **)buffer_get_index(&array, i));
        if (!node)
            continue;
        html_display_node(node, 0);
        printf("-------------------------------\n");
    }
    printf("Total forms: %u\n", array.size);
    buffer_free(&array);
}

int             web_shell_command_forminput(char *input, t_web_node *node)
{
    uint        i;
    uint        j;

    if (!input || !node)
        return (0);
    struct s_buf    array;
    array = html_find_tag(&node->html, "form");
    i = -1;
    while (++i < array.size)
    {
        t_html_node     *node;

        node = *((t_html_node **)buffer_get_index(&array, i));
        if (!node)
            continue;
        html_display_node_max(node, 0, 1);
        struct s_buf    input;
        input = html_find_tag(node, "input");
        j = -1;
        while (++j < input.size)
        {
            node = *((t_html_node **)buffer_get_index(&input, j));
            if (!node)
                continue;
            html_display_node(node, 1);
        }
        buffer_free(&input);
        printf("-------------------------------\n");
    }
    printf("Total forms: %u\n", array.size);
    buffer_free(&array);
}

int             web_shell(t_web_node *node)
{
    char            input[STRING_SIZE * 16]; // Pointeur pour la chaîne de caractères
    char            *output;
    char            *ptr;
    t_web_node      *child;
    size_t          len;
    uint            i;

    struct s_html_node  html;

    fd_set readfds;
    struct timeval timeout;

    memset(input, 0, STRING_SIZE * 16);
    input[0] = 'a';
    web_shell_display_prompt(node, 8);
    printf(">");
    while (strncmp(input, "exit", strlen("exit")) != 0 && strncmp(input, "return", strlen("return")) != 0)
    {
        //fflush(stdout); // S'assurer que l'invite est affichée immédiatement
        if (fgets(input, sizeof(input), stdin) != NULL)
        {
            len = strlen(input);
            if (len > 0 && input[len - 1] == '\n')
                input[len - 1] = '\0';
        }
        ///////////////////////////////////////////////////////////////
        /*
        fflush(stdout); // S'assurer que l'invite est affichée immédiatement

        // Initialiser le set de descripteurs
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        // Définir le timeout (par exemple, 5 secondes)
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        // Attendre que l'entrée soit prête
        int activity = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("select error");
            printf("STDIN_FILENO %d\n", STDIN_FILENO);//
            if (STDIN_FILENO < 0)
                perror("STDIN_FILENO est invalide");
            DEBUG //
            char test[10];
            if (read(STDIN_FILENO, test, sizeof(test)) < 0) {
                perror("Erreur de lecture sur stdin");
            } else {
                printf("Lecture réussie sur stdin\n");
            }
            DEBUG //
            return (0);
            //exit(EXIT_FAILURE);
        } else if (activity == 0) {
            continue;
        } else {
            // L'entrée est prête à être lue
            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                if (fgets(input, sizeof(input), stdin) != NULL) {
                    // Supprimer le caractère de nouvelle ligne
                    input[strcspn(input, "\n")] = '\0'; // Remplacer le '\n' par '\0'
                    ///printf("Vous avez saisi : %s\n", input);
                }
            }
        }
        */
        ///////////////////////////////////////////////////////////////
        /*
        else
        {
            DEBUG //
            if (node && !node->parent)
            {
                DEBUG //
                web_shell_command_export("export default.xml", node);
            }
            DEBUG //
            return (1);
        }*/
        if (strlen(input) == 0)
            continue;
        if (strncmp(input, "quit", strlen("quit")) == 0)
        {
            if (!node && node->parent)
            {
                web_shell_command_export("export default.xml", web_root_node(node));
            }
            return (1);
        }
        if (strncmp(input, "help", strlen("help")) == 0)
            web_shell_display_help();
        if (strncmp(input, "web_get_page", strlen("web_get_page")) == 0)
            web_shell_command_web_get_page(input, &node);
        if (!node)
            continue;
        if (strncmp(input, "info", strlen("info")) == 0)
            web_display_node(node);
        if (strncmp(input, "request", strlen("request")) == 0)
            http_display_request(&node->request);
        if (strncmp(input, "response", strlen("response")) == 0)
            http_display_response(&node->response);
        if (strncmp(input, "child", strlen("child")) == 0)
        {
            i = -1;
            while (++i < node->child.size)
            {
                child = *((t_web_node **)buffer_get_index(&node->child, i));
                printf("Child #%u ", i);
                web_display_node(child);
                printf("\n");
            }
        }
        if (strncmp(input, "goto", strlen("goto")) == 0)
            if (web_shell_command_goto(input, node))
            {
                if (node && !node->parent)
                {
                    web_shell_command_export("export default.xml", web_root_node(node));
                }
                return (1);
            }
        if (strncmp(input, "getword", strlen("getword")) == 0)
            web_shell_command_getword(input, node);
        if (strncmp(input, "texts", len) == 0)
            web_shell_command_texts(input, node);
        if (strncmp(input, "comments", len) == 0)
            web_shell_command_comments(input, node);
        if (strncmp(input, "texttag", strlen("texttag")) == 0)
            web_shell_command_texttag(input, node);
        if (strncmp(input, "htmldisplay", strlen("htmldisplay")) == 0)
        {///
            char *content;
            content = html_tostring(&node->html);
            //html_display_node(&node->html, 0);
            printf("%s\n", content);
        }///
        if (strncmp(input, "nodedisplay", strlen("htmldisplay")) == 0)
            html_display_node(&node->html, 0);
        if (strncmp(input, "export", strlen("export")) == 0)
            web_shell_command_export(input, node);
        if (strncmp(input, "save", strlen("save")) == 0)
            web_shell_command_export(input, web_root_node(node));
        if (strncmp(input, "import", strlen("import")) == 0)
            web_shell_command_import(input, node);
        if (strncmp(input, "links", len) == 0)
            web_shell_command_links(input, node);
        if (strncmp(input, "expand", strlen(input)) == 0)
            web_shell_command_expand(input, node);
            ///web_shell_command_expand_singlethread(input, node);
        if (strncmp(input, "expandsamesite", strlen("expandsamesite")) == 0)
            web_shell_command_expand_samesite(input, node);
        if (strncmp(input, "expandnotsamesite", strlen("expandnotsamesite")) == 0)
            web_shell_command_expand_notsamesite(input, node);
        if (strncmp(input, "expandallsamesite", strlen("expandallsamesite")) == 0)
            web_shell_command_expandallsamesite(input, node);
        if (strncmp(input, "expandallnotsamesite", strlen("expandallnotsamesite")) == 0)
            web_shell_command_expandallnotsamesite(input, node);
        if (strncmp(input, "mail", strlen("mail")) == 0)
            web_shell_command_mail(input, node);
        if (strncmp(input, "delete", strlen("delete")) == 0)
            web_shell_command_delete(input, node);
        if (strncmp(input, "host", strlen("host")) == 0)
            if (web_shell_command_host(input, node))
                return (1);
        if (strncmp(input, "forminput", strlen("forminput")) == 0)
            web_shell_command_forminput(input, node);
        else if (strncmp(input, "form", strlen("form")) == 0)
            web_shell_command_form(input, node);
        if (strncmp(input, "content", STRING_SIZE) == 0)
        {
            if (node->response.buf)
                printf("%s\n", node->response.buf);
        }
        web_shell_display_prompt(node, 8);
        printf(">");
    }
    return (0);
}

void            test_import_export(char *seed)
{
    /*
    struct s_http_response  page;

    //page = web_get_page("http://wikipedia.org/");
    page = web_get_page("http://info.cern.ch/");
    http_display_response(&page);

    http_response_export_xml(&page);
    */
    t_web_node          *root;

    if (!(root = web_new_node(seed, NULL, 3)))
        printf("Error\n");
    char *xml;

    web_shell(root);
    return ;
    xml = web_export_xml(root);
    printf("XML ==========================================\n\n%s\n", xml);

    t_html_node *html;

    html = html_new_node(xml, NULL, NULL);
    printf("------------------------------------\n\n");
    ///html_display_node(html, 0);

    //web_free_node(root);
    //FREE(root);
    //if (!(root = web_import_xml(xml)))
    //    printf("Error\n");
    printf("--------------------------------------"); //
    //FREE(xml);
    //xml = web_export_xml(root);
    printf("XML ==========================================\n\n%s\n", xml);
    //web_free_node(root);
    //FREE(root);
}

void            test_web(void)
{
    struct s_http_response  page;

    page = web_get_page("http://info.cern.ch/", NULL);
    http_display_response(&page);

    struct s_html_node  root;
    root = html_parse(page.buf);
    html_display_node(&root, 0);
}

void            test_json(void)
{
    t_json_node *root;
    char        *json = "{a:22,b : 'abc',{'c':33}}";

    if (!(root = json_new_node(json, NULL, NULL)))
        return ;

    char *str;
    if (!(str = json_tostring(root)))
        return ;
    printf("Json : [%s]\n", str);

    struct s_buf   list;
    list = json_get_param(root, "a");
    buffer_display_param_list(&list);
}

void            test_http(char *url)
{
    struct s_http_request   request;
    struct s_buf            param;
    struct s_buf            header;
    uint                    recvlength;
    char                    *recv;

    /*
    param = buffer_new_param_list(1, "id='0'");
    header = buffer_new_param_list(1, "User-Agent='custom'");
    request = http_new_request("http://127.0.0.1:1234/", "GET", &param, &header);
    */
    header = buffer_new_param_list(1, "User-Agent='custom'");
    request = http_new_request("http://www.wikipedia.org/", "GET", NULL, &header, NULL);
    if (!(recv = http_send_request(&request, &recvlength)))
    {
        printf("Error\n");
        return ;
    }
    printf("RECV [%s]\n", recv);

    struct s_http_response response;
    response = http_new_response(recv, NULL);

    http_display_response(&response);
}

void            test_parser(void)
{
    struct s_html_node     root;
    struct s_buf    list;
    int             i;
    char *html = "<!DOCTYPE html>\
    <html param='abc' str='def'>\
        <!-- TEST1 -->\
        <!--TEST2 -->\
        <!--TEST3-->\
        <!--         TEST4-->\
        <!--         TEST5             -->\
        <!--TEST6             -->\
        <p>\
            ghi\
        </p>\
    </html>";

    root = html_parse(html);

    printf("-----------------------\n");//
    html_display_node(&root, 0);
    printf("-----------------------\n");//
    list = html_find_node_param(&root, "href", "localhostt");
    i = -1;
    printf("List size [%u]\n", list.size);
    debug_display_ptr(&list);
    while (++i < list.size)
        html_display_node(*((t_html_node **)buffer_get_index(&list, i)), 0);
        ///buffer_display_param(*((t_buf_param **)buffer_get_index(&list, i)), 0);
    buffer_free(&list);
}

void        test_connection(void)
{
    struct s_net_connection con;
    char *host;

    //char            *onion = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/";
    //char            *onion = "http://bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion/";
    char            *onion = "http://hellhoh5o35sylxrpfu45p5r74n2lzvirnvszmziuvn7bcejlynaqxyd.onion/";
    printf("New onion connection\n");
    host = url_get_host(onion);
    printf("Is onion [%d]\n", url_host_is_onion(host));
    //con = net_new_connection("127.0.0.1", 3128, 0); // Squid
    con = net_new_onion_connection(host, 80, 0);
    //con = net_new_connection("127.0.0.1", 9050, 0); //
    printf("Connecting...\n");
    if (net_connect(&con))
    {
        printf("Connection error\n");
        return ;
    }
    printf("Connected\n");

    char *path = "/index.html";
        // Préparer la requête HTTP GET
    char request[1024];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n", path, host);

    printf("REQUEST [%s]\n", request);

    // Envoyer la requête HTTP
    if (send(con.sock, request, strlen(request), 0) < 0) {
        perror("Failed to send HTTP request");
        return;
    }

    // Lire la réponse HTTP
    char response[4096];
    ssize_t bytes_received;
    while ((bytes_received = recv(con.sock, response, sizeof(response) - 1, 0)) > 0) {
        response[bytes_received] = '\0'; // Null-terminate the response
        printf("%s", response); // Afficher la réponse
    }

    if (bytes_received < 0) {
        perror("Error receiving response");
    }
}

#ifdef _WIN32
void        test_windows_connection()
{
        WSADATA WSAData;
    SOCKET sock;
    SOCKADDR_IN sin;
    char buffer[255];
    WSAStartup(MAKEWORD(2,0), &WSAData);
    /* Tout est configuré pour se connecter sur IRC, haarlem, Undernet. */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_family = AF_INET;
    sin.sin_port = htons(1025);
    printf("Connect : %d\n", connect(sock, (SOCKADDR *)&sin, sizeof(sin)));
    buffer[0] = 'a';
    buffer[1] = '\0';
    send(sock, buffer, 5, 0);
    recv(sock, buffer, sizeof(buffer), 0);
    closesocket(sock);
    WSACleanup();
}
#endif

int test_socks5()
{
    #define SOCKS5_VERSION 0x05
    #define SOCKS5_CMD_CONNECT 0x01
    #define SOCKS5_ATYP_DOMAIN 0x03
    int sock;
    struct sockaddr_in server_addr;
    char request[1024];
    const char *onion_address = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion";
    int port = 80; // Change to 443 for HTTPS

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Set up the SOCKS5 proxy address (Tor)
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9050); // Tor's SOCKS5 port
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Connect to the SOCKS5 proxy
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to SOCKS5 proxy failed");
        close(sock);
        return 1;
    }

    // Send SOCKS5 connection request
    int address_length = strlen(onion_address);
    request[0] = SOCKS5_VERSION; // Version
    request[1] = SOCKS5_CMD_CONNECT; // Command
    request[2] = 0; // Reserved
    request[3] = SOCKS5_ATYP_DOMAIN; // Address type (domain)
    request[4] = address_length; // Length of domain name
    memcpy(&request[5], onion_address, address_length); // Domain name
    // Set the destination port (2 bytes, network byte order)
    request[5 + address_length] = (port >> 8) & 0xFF; // High byte
    request[6 + address_length] = port & 0xFF;        // Low byte

    // Send the SOCKS5 connection request
    int request_length = 7 + address_length; // 1 (version) + 1 (command) + 1 (reserved) + 1 (address type) + 1 (length) + length of domain + 2 (port)
    if (send(sock, request, request_length, 0) < 0) {
        perror("Failed to send SOCKS5 request");
        close(sock);
        return 1;
    }

    // Receive the SOCKS5 response
    char response[10]; // Buffer for the response
    if (recv(sock, response, sizeof(response), 0) < 0) {
        perror("Failed to receive SOCKS5 response");
        close(sock);
        return 1;
    }

    // Check the response
    if (response[1] != 0x00) { // Check if the command succeeded
        fprintf(stderr, "SOCKS5 connection failed: %d\n", response[1]);
        close(sock);
        return 1;
    }

    // Successfully connected to the .onion service
    printf("Successfully connected to %s:%d through SOCKS5 proxy.\n", onion_address, port);

    // Now you can send HTTP requests or other data through the established connection
    // Example: Sending an HTTP GET request
    char http_request[1024];
    snprintf(http_request, sizeof(http_request),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n", onion_address);

    // Send the HTTP request
    send(sock, http_request, strlen(http_request), 0);

    // Receive the HTTP response
    char buffer[4096];
    int bytes_received;
    while ((bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the buffer
        printf("%s", buffer); // Print the response
    }

    // Close the socket
    close(sock);
    return 0;
}

int         test_ipv6(void)
{
    const char *ip = "2001:1458:201:a4::100:1a0"; // Remplacez par l'adresse IPv6 cible
    int port = 80; // Remplacez par le port cible
    int sock;
    struct sockaddr_in6 server_6;

    // Créer le socket
    sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Erreur lors de la création du socket");
        return 1;
    }

    // Configurer l'adresse du serveur
    memset(&server_6, 0, sizeof(server_6));
    server_6.sin6_family = AF_INET6;
    server_6.sin6_port = htons(port);

    // Convertir l'adresse IPv6
    if (inet_pton(AF_INET6, ip, &server_6.sin6_addr) <= 0) {
        perror("Erreur lors de la conversion de l'adresse IP");
        close(sock);
        return 1;
    }

    // Établir la connexion
    if (connect(sock, (struct sockaddr *)&server_6, sizeof(server_6)) == -1) {
        perror("Erreur lors de la connexion");
        close(sock);
        return 1;
    }

    printf("Connexion réussie à %s sur le port %d\n", ip, port);

    // Fermer le socket
    close(sock);
    return 0;
}

int main(int ac, char **av)
{
    t_web_node  *node;


    if (1)
    {
        if (ac == 2)
        {
            node = web_new_node(av[1], NULL, 1);
            web_shell_command_import("import default.xml", node);
            //node = web_new_node("http://hellhoh5o35sylxrpfu45p5r74n2lzvirnvszmziuvn7bcejlynaqxyd.onion/", NULL, 1);
            //node = web_new_node("http://www.allorank.com/", NULL, 1);
            web_shell(node);
        }
        else
        {
            web_shell(NULL);
        }
    }
    return (0);
}
