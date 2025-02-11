#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC(x) malloc(x)
#define FREE(x) free(x)
#define DEBUG printf("%s : %d\n", __func__, __LINE__);

// Ne pas oublier -lws2_32 sur Windows
// Ligne 1071 macro Windows/Linux
#define STRING_SIZE 128

typedef unsigned int uint;

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

void debug_string(char *str, uint count)
{
    printf("DEBUG STRING [");
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

void                *html_free_node(t_html_node *node)
{
    uint            i;

    if (!node)
        return (NULL);
    i = -1;
    while (++i < node->param.size)
        buffer_free_param((t_buf_param *)buffer_get_index(node->param.buf, i));
    i = -1;
    while (++i < node->child.size)
        html_free_node((t_html_node *)buffer_get_index(node->child.buf, i));
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

    size = strlen(str) + 1;
    if (!(dup = ALLOC(size)))
        return (NULL);
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
    ///printf("\t\t\t\t\t\t\tparam @ %p\n", param);
    ///buffer_display_param(param, 9);//
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
    memcpy(dst->buf + (dst->blocksize * size), src->buf, src->blocksize * src->size);
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

int                 html_is_inline(char *tag, char *trail)
{
    if (*(trail - 2) == '/') // Test TODO
        return (1);
    while (*trail)
    {
        if (*trail == '<')
        {
            if (*(trail + 1) == '/')
            {
                trail += 2;
                if (strncasecmp(tag, trail, strlen(tag)) == 0)
                    return (0);
            }
            /// else /// TODO
            /// Need more sophisticated function
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

    if (!trail || !tagname)
        return (NULL);
    while (*trail)
    {
        if (strlen(trail) < 3 + strlen(tagname))
            return (trail);
        if (trail[0] == '<' && trail[1] == '/')
        {
            end = trail;
            trail += 2;
            if (strncasecmp(tagname, trail, strlen(tagname)) == 0)
            {
                trail += strlen(tagname);
                trail = string_goto(trail, '>');
                if (*trail == '>')
                    return (end);
            }
        }
        else if (trail[0] == '\'' || trail == '"')
        {
            trail = string_skip_string(trail);
            if (!*trail)
                return (trail);
        }
        trail++;
    }
    return (trail);
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
    node->param.blocksize = sizeof(t_buf_param);
    node->child.blocksize = sizeof(t_html_node);
    string = NULL;
    trail = tag;
    if (parent // Special case
        && html_is_special_tag(parent->tag))
    {
        endofstring = string_goto_endtag(parent->tag, trail);
        node->text = string_duplicate(trail, endofstring - trail);
        trail = string_goto(endofstring + strlen(parent->tag) + 2, '>');
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
    if (!(trail = string_goto_alphanum(trail)) ||
        !(endofstring = string_goto_multiple(trail, "\n\t />")))
        return (html_free_node(node));
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
    trail++; // Inner
    node->is_inline = html_is_inline(node->tag, trail);
    if (!node->is_inline
        //&& strncasecmp(node->tag, "style", STRING_SIZE) != 0
        )
        while ((inner_node = html_new_node(trail, node, &nexttag))) // Recursion
        {
            if (buffer_realloc(&node->child, node->child.size + 1))
                return (html_free_node(node));
            buffer_set_index(&node->child, node->child.size - 1, inner_node);
            trail = nexttag;
            if (html_is_special_tag(node->tag))
                break;
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
        param = *((t_buf_param **)buffer_get_index(buf, i));
        //param = buffer_get_index(buf, i);
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

char                        *html_get_text(t_html_node *html)
{
    char        *text;

    text = NULL;
    if (html->text)
    {
        text = string_stradd(text, html->text);
        text = string_stradd(text, "\n");
    }
    uint        i;
    t_html_node *child;
    i = -1;
    while (++i < html->child.size)
    {
        child = *((t_html_node **)buffer_get_index(&html->child, i));
        text = string_stradd(text, html_get_text(child));
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
        buffer = string_stradd(buffer, " ");
        i = -1;
        while (++i < html->param.size)
        {
            param = *((t_buf_param **)buffer_get_index(&html->param, i));
            string = buffer_param_tostring_html(param);
            buffer = string_stradd(buffer, string);
            FREE(string);
            buffer = string_stradd(buffer, " ");
        }
        if (html->is_inline)
            buffer = string_stradd(buffer, "/");
        buffer = string_stradd(buffer, ">");
    }
    if (html->text)
        buffer = string_stradd(buffer, html->text);
    i = -1;
    while (++i < html->child.size)
    {
        child = *((t_html_node **)buffer_get_index(&html->child, i));
        string = html_tostring(child);
        buffer = string_stradd(buffer, string);
    }
    if (!html->is_inline)
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
        if (buffer_realloc(&root.child, root.child.size + 1))
        {
            html_free_node(node);
            return (root);
        }
        buffer_set_index(&root.child, count++, node);
    }
    return (root);
}

////////////////////////////////////////////////////////////

#define _WIN32
///#define SSL_ENABLED
#ifdef _WIN32
// Windows-specific includes
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <sys/socket.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h> // read(), write(), close()
#define SA struct sockaddr

typedef struct s_net_connection
{
    char        connected;
    char        ip[17];
    #ifdef _WIN32
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    #else
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;
    #endif
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
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Set the default verification paths
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
}
#endif

struct s_net_connection     net_new_connection(char *ip, int port, int ssl)
{
    struct s_net_connection     con;

    printf("Connecting to [%s] Port: %d\n", ip, port);
    memset(&con, 0, sizeof(struct s_net_connection));
    if (!ip || port < 0)
        return (con);
    strncpy(con.ip, ip, 16);
    #ifdef _WIN32
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &con.wsaData) != 0)
        return (con);
    #ifdef SSL_ENABLED
    // Init OpenSSL
    if (ssl)
    {
        con.ssl_enabled = 1;
        init_openssl();
        con.ctx = create_context();
        configure_context(con.ctx);
    }
    #endif
    // Create a socket
    con.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (con.sock == INVALID_SOCKET)
    {
        WSACleanup();
        return (con);
    }

    // Set up the server address structure
    con.server.sin_family = AF_INET;
    con.server.sin_port = htons(port); // Port number
    con.server.sin_addr.s_addr = inet_addr(ip); // Ip
    #else
    // socket create and verification
    con.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (con.sockfd == -1)
        return (con);
    #ifdef SSL_ENABLED
    // Init OpenSSL
    if (ssl)
    {
        con.ssl_enabled = 1;
        init_openssl();
        con.ctx = create_context();
        configure_context(con.ctx);
    }
    #endif
    // assign IP, PORT
    con.servaddr.sin_family = AF_INET;
    con.servaddr.sin_addr.s_addr = inet_addr(ip);
    con.servaddr.sin_port = htons(port);
    #endif
    return (con);
}

int             net_connect(t_net_connection *con)
{
    if (!con || con->connected == 1)
        return (1);
    #ifdef _WIN32
    #ifdef SSL_ENABLED
    if (con->ssl_enabled)
    {
        // Create SSL connection
        con->ssl = SSL_new(con->ctx);
        SSL_set_fd(con->ssl, con->sock);
        // Establish SSL connection
        if (SSL_connect(con->ssl) <= 0)
            return (1);
    }
    else
    #endif
    {
        // Connect to the server
        if (connect(con->sock, (struct sockaddr *)&con->server, sizeof(con->server)) < 0)
        {
            closesocket(con->sock);
            WSACleanup();
            return (1);
        }
    }
    #else
    #ifdef SSL_ENABLED
    if (con->ssl_enabled)
    {
        // Create SSL connection
        con->ssl = SSL_new(con->ctx);
        SSL_set_fd(con->ssl, con->sock);
        // Establish SSL connection
        if (SSL_connect(con->ssl) <= 0)
            ERR_print_errors_fp(stdout)
    }
    else
    #endif
    {
        // connect the client socket to server socket
        if (connect(con->sockfd, (SA*)&con->servaddr, sizeof(con->servaddr)) != 0)
            return (1);
    }
    #endif
    con->connected = 1;
    return (0);
}

int             net_disconnect(t_net_connection *con)
{
    if (!con || con->connected == 0)
        return (1);
    #ifdef _WIN32
    // Clean up
    #ifdef SSL_ENABLED
    if (con->ssl_enabled)
    {
        con->ssl_enabled = 0;
        SSL_free(con->ssl);
        SSL_CTX_free(con->ctx);
        cleanup_openssl();
    }
    #endif
    closesocket(con->sock);
    WSACleanup();
    #else
    // close the socket
    if (con->ssl_enabled)
    {
        con->ssl_enabled = 0;
        SSL_free(con->ssl);
        SSL_CTX_free(con->ctx);
        cleanup_openssl();
    }
    close(con->sockfd);
    #endif
    con->connected = 0;
    return (0);
}

int             net_send(t_net_connection *con, char *data, uint *length)
{
    if (!con)
        return (1);
    if (con->connected == 0 && net_connect(con))
        return (1);
    #ifdef _WIN32
    if (length)
    {
        printf("Sending %u bytes\n", *length);
        #ifdef SSL_ENABLED
        if (con->ssl_enabled)
        {
            SSL_write(con->ssl, data, *length);
        }
        else
        #endif
        {
            if (send(con->sock, data, *length, 0) == SOCKET_ERROR)
                return (1);
        }
        return (0);
    }
    printf("Sending %zu bytes\n", strlen(data));
    #ifdef SSL_ENABLED
    if (con->ssl_enabled)
    {
        SSL_write(con->ssl, data, strlen(data));
    }
    else
    #endif
    {
        if (send(con->sock, data, strlen(data), 0) == SOCKET_ERROR)
            return (1);
    }
    return (0);
    #else
    if (length)
        write(con->sockfd, data, *length);
    else
        write(con->sockfd, data, strlen(data));
    #endif
    return (0);
}

char            *net_recv(t_net_connection *con, uint *length)
{
    size_t          rd;
    struct s_buf    readed;
    struct s_buf    string;
    char            buff[STRING_SIZE];

    if (!con)
        return (NULL);
    if (con->connected == 0 && net_connect(con))
        return (NULL);
    readed.blocksize = 1;
    readed.buf = &buff;
    readed.size = 0;
    string = buffer_new(1, 0);
    printf("Receiving\n");
    #ifdef _WIN32
    while ((rd = recv(con->sock, buff, STRING_SIZE, 0)) > 0)
    #else
    while ((rd = read(con->sockfd, buff, STRING_SIZE)) > 0)
    #endif
    {
        readed.size = rd;
        if (length)
            *length += rd;
        if (buffer_concat(&string, &readed))
        {
            buffer_free(&string);
            return (NULL);
        }
    }
    if (rd == -1)
    {
        buffer_free(&string);
        return (NULL);
    }
    printf("Received %u bytes\n", string.size);
    return ((char *)string.buf);
}

char            *net_send_recv(t_net_connection *con, char *data, uint *send_length, uint *recv_length)
{
    net_send(con, data, send_length);
    return (net_recv(con, recv_length));
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
    if (!*endofstring)
        return (NULL);
    size = endofstring - url;
    if (!(host = ALLOC(size + 1)))
        return (NULL);
    memset(host, 0, size + 1);
    return (strncpy(host, url, size));
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
        return (NULL);
    url = endofstring;
    size = strlen(url);
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

char        *net_resolve_domain(const char *domain)
{
    WSADATA         wsaData;
    char            *ret;
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN]; // Buffer to hold the IP address string

    if (!domain)
        return (NULL);
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return (NULL);
    }

    ret = NULL;
    // Set up the hints structure
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_UNSPEC means we don't care if it's IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
    hints.ai_flags |= AI_CANONNAME; // Test

    // Get the address info
    if ((status = getaddrinfo(domain, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return (NULL);
    }
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

        // Convert the IP to a string and print it
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("Resolved IP: %s\n", ipstr);
        ret = string_strdup(ipstr);
    }
    // Free the linked list
    freeaddrinfo(res);
    return (ret);
}

int                             url_is_ipv4(char *host)
{
    int         count;
    int         i;
    char        *hostname;

    if (!(hostname = url_get_host(host)))
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

struct s_net_connection         url_new_connection(char *url)
{
    struct s_net_connection     con;
    char                        *host;
    char                        *ip;

    memset(&con, 0, sizeof(struct s_net_connection));
    if (!(host = url_get_host(url)))
        return (con);
    printf("New connection to [%s]\n", host);
    if (url_is_ipv4(host))
    {
        if (!(ip = string_strdup(host)))
        {
            FREE(host);
            return (con);
        }
    }
    else
    {
        if (!(ip = net_resolve_domain(host)))
        {
            FREE(host);
            return (con);
        }
    }
    con = net_new_connection(ip, url_get_port(url), url_is_https(url));
    FREE(ip);
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

char            *http_send_request(t_http_request *request, uint *recv_length)
{
    char                    *http;
    struct s_net_connection con;
    int                     i;
    t_json_node             *json;
    t_buf_param             *param;
    char                    *string;
    char                    *route;
    char                    *host;
    char                    *ret;

    if (!request)
        return (NULL);
    if (url_is_https(request->url) == 1)
        return (NULL);
    con = url_new_connection(request->url);
    if (net_connect(&con))
        return (NULL);
    printf("Url [%s]\n", request->url);
    if (!(host = url_get_host(request->url)))
        return (NULL);
    printf("Host [%s]\n", host);
    if (!(route = url_get_route(request->url)))
    {
        FREE(host);
        return (NULL);
    }
    printf("Route [%s]\n", route);
    http = NULL;
    http = string_stradd(http, request->method);
    http = string_stradd(http, " ");
    http = string_stradd(http, route);
    FREE(route);
    i = -1;
    printf("Param :\n");
    while (++i < request->param.size)
    {
        param = *((t_buf_param **)buffer_get_index(&request->param, i));
        buffer_display_param(param, 1);
        http = string_stradd(http, param->name);
        http = string_stradd(http, "=");
        http = string_stradd(http, param->data.buf);
        if (i + 1 < request->param.size - 1)
            http = string_stradd(http, "&");
    }
    http = string_stradd(http, " HTTP/1.1\r\n");
    printf("Headers :\n");
    if (!url_is_ipv4(host))
    {
        http = string_stradd(http, "Host: ");
        http = string_stradd(http, host);
        http = string_stradd(http, "\r\n");
    }
    FREE(host);
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
        buffer_display_param(param, 1);
        http = string_stradd(http, param->name);
        http = string_stradd(http, ": ");
        http = string_stradd(http, param->data.buf);
        http = string_stradd(http, "\r\n");
    }
    if (strlen(request->content.type) != 0)
    {
        http = string_stradd(http, "\r\n");
        printf("Content : [%s]\n", request->content.type);
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
    ///printf("%s\n", http);
    ret = net_send_recv(&con, http, NULL, recv_length);
    FREE(http);
    net_disconnect(&con);
    return (ret);
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

struct s_http_response         http_new_response(char *http)
{
    t_buf_param                 *param;
    struct s_http_response      response;
    char                        *res;
    char                        *ptr;
    char                        *endofstring;

    memset(&response, 0, sizeof(struct s_http_response));
    if (!http)
        return (response);
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
        if (strncasecmp(param->name, "Content-Type", strlen("Content-Type")) == 0)
        {
            strncpy(response.content_type, param->name, STRING_SIZE);
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
    //debug_string(ptr, 10);
    if (0 && response.content_length != 0)
    {
        DEBUG //
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
        response.buf = strdup(ptr);
    }
    FREE(res);
    return (response);
}

int                 url_is_relative(char *url)
{
    char        *proto;

    if (!(proto = url_get_proto(url)))
        return (1);
    FREE(proto);
    return (0);
}

char                *url_get_full(char *src, char *relative)
{
    char        *full;
    char        *proto;
    char        *host;

    if (!src || !relative)
        return (NULL);
    if (!url_is_relative(relative))
        return (strdup(relative));
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
    if (*relative != '/')
        full = string_stradd(full, "/");
    full = string_stradd(full, relative);
    FREE(proto);
    FREE(host);
    return (full);
}

struct s_http_response  web_get_page(char *url, t_http_request *out)
{
    struct s_buf            header;
    struct s_http_request   request;
    struct s_http_response  response;
    struct s_http_response  redirect;
    char                    *recv;
    char                    *host;
    char                    *hostname;

    memset(&response, 0, sizeof(struct s_http_response));
    printf("GET_PAGE [%s]\n", url); //
    if (!url_is_ipv4(url) && (hostname = url_get_host(url)))
    {
        host = string_stradd(NULL, "Host='");
        host = string_stradd(host, hostname);
        host = string_stradd(host, "'");
        header = buffer_new_param_list(2, "User-Agent='custom'", host);
        FREE(host);
        FREE(hostname);
    }
    else
        header = buffer_new_param_list(1, "User-Agent='custom'");
    request = http_new_request(url, "GET", NULL, &header, NULL);
    if (!(recv = http_send_request(&request, NULL)))
    {
        http_free_request(&request);
        return (response);
    }
    printf("RECV [%s]\n", recv); //
    response = http_new_response(recv);
    FREE(recv);
    if (response.code == 301 || response.code == 302)
    {
        char *full_url;
        char *location_url;
        location_url = buffer_param_get_var_buf(&response.header, "location");
        if (url_is_relative(location_url))
            full_url = url_get_full(request.url, location_url);
        else
            full_url = strdup(location_url);
        if (strncmp(
                    request.url,
                    full_url,
                    strlen(full_url)
                ) == 0)
        {
            if (out)
            {
                http_display_request(&request);
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
    if (out)
        memcpy(out, &request, sizeof(struct s_http_request));
    else
        http_free_request(&request);
    return (response);
}

typedef struct s_web_node
{
    struct s_http_request   request;
    struct s_http_response  response;
    struct s_web_node       *parent;
    struct s_buf            child;
}               t_web_node;

void            web_free_node(t_web_node *node)
{
    t_web_node  *child;
    uint        i;

    http_free_request(&node->request);
    http_free_response(&node->response);
    i = -1;
    while (++i < node->child.size)
    {
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        web_free_node(child);
        FREE(child);
    }
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
    xml = string_stradd_len(xml, response->buf, response->content_length);
    xml = string_stradd(xml, "</content>");
    xml = string_stradd(xml, "</response>");
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
    printf("Child count #%u\n", node->child.size);
    i = -1;
    while (++i < node->child.size)
    {
        //child = buffer_get_index(&node->child, i);
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        printf("\t(%p)\n", child);
    }
}

char            *web_export_xml(t_web_node *node)
{
    t_web_node          *child;
    char                *xml;
    uint                i;

    if (!node)
        return (NULL);
    DEBUG //
    xml = string_stradd(NULL, "<web>");
    DEBUG //
    web_display_node(node);
    DEBUG //
    http_display_request(&node->request); //
    DEBUG //
    xml = string_stradd(xml, http_request_export_xml(&node->request));
    DEBUG //
    xml = string_stradd(xml, http_response_export_xml(&node->response));
    DEBUG //
    i = -1;
    while (++i < node->child.size)
    {
        DEBUG //
        child = *((t_web_node **)buffer_get_index(&node->child, i));
        //child = buffer_get_index(&node->child, i);
        xml = string_stradd(xml, web_export_xml(child));
    }
    DEBUG //
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

    DEBUG //
    if (!param)
        return (NULL);
    if (!(copy = ALLOC(sizeof(struct s_buf_param))))
        return (NULL);
    DEBUG //
    buffer_display_param(param, 4);//
    DEBUG //
    strncpy(copy->name, param->name, STRING_SIZE - 1);
    DEBUG //
    copy->data = buffer_copy_buf(&param->data);
    DEBUG //
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
    list = html_find_tag_max(node, "reponse", 1);
    if (list.size == 0)
        return (response);
    resnode = *((t_html_node **)buffer_get_index(&list, 0));
    if (!(ptr = buffer_param_get_var_buf(&resnode->param, "version")))
        return (response);
    strncpy(response.http_version, ptr, STRING_SIZE - 1);

    if (!(ptr = buffer_param_get_var_buf(&resnode->param, "code")))
        return (response);
    response.code = atoi(ptr);

    buffer_free(&list);
    list = html_find_tag_max(resnode, "header", 1);
    i = -1;
    while (++i < list.size)
    {
        paramnode = *((t_html_node **)buffer_get_index(&list, i));
        param = *((t_buf_param **)buffer_get_index(&paramnode->param, i));
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
    if (!(response.buf = html_tostring(resnode)))
    {
        http_free_response(&response);
        return (response);
    }
    return (response);
}

struct s_http_request   http_request_import_xml(t_html_node *node)
{
    struct s_http_request   request;
    struct s_buf            list;
    t_buf_param             *param;
    t_html_node             *reqnode;
    t_html_node             *paramnode;
    char                    *ptr;
    uint                    i;

    memset(&request, 0, sizeof(struct s_http_request));
    list = html_find_tag_max(node, "request", 1);
    if (list.size == 0)
        return (request);
    reqnode = *((t_html_node **)buffer_get_index(&list, 0));
    if (!(ptr = buffer_param_get_var_buf(&reqnode->param, "method")))
        return (request);
    strncpy(request.method, ptr, STRING_SIZE - 1);
    if (!(ptr = buffer_param_get_var_buf(&reqnode->param, "url")))
        return (request);
    request.url = strdup(ptr);
    buffer_free(&list);
    list = html_find_tag_max(reqnode, "param", 1);
    i = -1;
    while (++i < list.size)
    {
        paramnode = *((t_html_node **)buffer_get_index(&list, i));
        param = *((t_buf_param **)buffer_get_index(&paramnode->param, i));
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
        param = buffer_get_index(&paramnode->param, i);
        //param = *((t_buf_param **)buffer_get_index(&paramnode->param, i));
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
    struct s_buf        list;
    uint                i;

    if (!node)
        return (NULL);
    if (!(web = ALLOC(sizeof(struct s_web_node))))
        return (NULL);
    web->parent = parent;
    web->request = http_request_import_xml(node);
    web->response = http_response_import_xml(node);

    list = html_find_tag_max(node, "web", 2);
    i = 0;
    while (++i < list.size)
    {
        child = *((t_html_node **)buffer_get_index(&list, i));
        if (!(child_web = web_import_xml_node(child, web)))
        {
            web_free_node(web);
            FREE(web);
            return (NULL);
        }
        buffer_push(&web->child, &child_web);
    }
    buffer_free(&list);
    return (web);
}

t_web_node          *web_import_xml(char *xml)
{
    t_web_node              *web;
    t_html_node             *root;

    if (!(root = html_new_node(xml, NULL, NULL)))
        return (NULL);
    //html_free_node(root);
    //return (NULL);
    web = web_import_xml_node(root, NULL);
    DEBUG //
    html_display_node(root, 0); // DEBUG
    html_free_node(root);
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
    if (strncmp(node->request.url, url, strlen(url)) == 0)
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
    if (!(node = ALLOC(sizeof(struct s_web_node))))
        return (NULL);
    memset(node, 0, sizeof(struct s_web_node));
    node->parent = parent;
    page = web_get_page(url, &node->request);

    root = html_parse(page.buf);
    html_display_node(&root, 0);

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
                printf("HREF == [%s]\n", (char *)param->data.buf); //
                printf("Press enter to continue\n");//
                getchar();
                full_url = url_get_full(url, param->data.buf);
                if (web_url_exists(web_root_node(node), full_url))
                {
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
    return (node);
}

void            web_shell_display_prompt(t_web_node *node)
{
    if (!node)
        return ;
    web_shell_display_prompt(node->parent);
    printf("%s -\n", node->request.url);
}

void            web_shell_display_help(void)
{
    printf("----- HELP -----\n");
    printf("exit : Return to parent node\n");
    printf("return : Return to parent node\n");
    printf("quit : Exit shell\n");
    printf("info : Node informations\n");
    printf("request : Display request\n");
    printf("response : Display reponse\n");
    printf("child : Display childs\n");
    printf("goto : Goto child\n");
    printf("export : Export to XML\n");
    printf("content : View node content\n");
    printf("----------------\n");
}

int             web_shell(t_web_node *node)
{
    char            input[STRING_SIZE]; // Pointeur pour la chaîne de caractères
    char            *output;
    char            *ptr;
    t_web_node      *child;
    size_t          len;
    uint            i;

    if (!node)
        return (0);
    memset(input, 0, STRING_SIZE);
    input[0] = 'a';
    while (strncmp(input, "exit", strlen("exit")) != 0 && strncmp(input, "return", strlen("return")) != 0)
    {
        web_shell_display_prompt(node);
        printf(">");
        if (fgets(input, sizeof(input), stdin) != NULL)
        {
            len = strlen(input);
            if (len > 0 && input[len - 1] == '\n')
                input[len - 1] = '\0';
        }
        else
            return (1);
        if (strncmp(input, "quit", strlen("quit")) == 0)
            return (1);
        if (strncmp(input, "help", strlen("help")) == 0)
            web_shell_display_help();
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
        {
            if ((ptr = string_goto_numeric(input)))
            {
                i = atoi(ptr);
                child = *((t_web_node **)buffer_get_index(&node->child, (uint)i));
                if (!child)
                    printf("Bad child index\n");
                else if (web_shell(child))
                    return (1);
            }
        }
        if (strncmp(input, "export", len) == 0)
        {
            output = web_export_xml(node);
            printf("%s\n", output);
            FREE(output);
        }
        if (strncmp(input, "content", STRING_SIZE) == 0)
            printf("%s\n", node->response.buf);
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

    DEBUG //
    if (!(root = web_new_node(seed, NULL, 2)))
        printf("Error\n");
    DEBUG //
    char *xml;

    web_shell(root);
    return ;
    DEBUG //
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

    //page = web_get_page("http://wikipedia.org/");
    page = web_get_page_OLD("http://info.cern.ch/");
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
    response = http_new_response(recv);

    http_display_response(&response);
}

void            test_parser(void)
{
    struct s_html_node     root;
    struct s_buf    list;
    int             i;
    char *html = "<!DOCTYPE html>\
    <html param='abc' str='def'>\
        <p>\
            ghi\
        </p>\
        <p>\
            jkl\
            <a href=\"localhost\">lmn</a>\
            opq\
        </p>\
        <img/>\
        <img/>\
    </html>";

    root = html_parse(html);

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

    con = net_new_connection("127.0.0.1", 1234, 0);
    net_send(&con, "Hello", NULL);
}

int main(int ac, char **av)
{
    //test_http(av[1]);
    //test_web();
    test_import_export(av[1]);
    return (0);
}
