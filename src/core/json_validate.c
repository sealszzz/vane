#include "vane/common.h"
#include "json_validate.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct scanner {
    const char *s;
    size_t len;
    size_t pos;
    size_t depth;
    struct vane_error *err;
};

#define VANE_JSON_MAX_DEPTH 64U

static void skip_ws(struct scanner *sc) {
    while (sc->pos < sc->len) {
        char c = sc->s[sc->pos];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            break;
        }
        sc->pos++;
    }
}

static bool fail(struct scanner *sc, const char *msg) {
    vane_error_set(sc->err, "invalid JSON at byte %zu: %s", sc->pos, msg);
    return false;
}

static bool hex4(struct scanner *sc, uint32_t *out) {
    if (sc->len - sc->pos < 4) {
        return fail(sc, "truncated unicode escape");
    }
    uint32_t v = 0;
    for (size_t i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)sc->s[sc->pos++];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
        else return fail(sc, "invalid unicode escape");
    }
    *out = v;
    return true;
}


static bool decode_utf8(struct scanner *sc, unsigned char first, uint32_t *out) {
    size_t continuation_count = 0U;
    uint32_t cp = 0U;
    unsigned char second_min = 0x80U, second_max = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
        continuation_count = 1U;
        cp = (uint32_t)(first & 0x1fU);
    } else if (first >= 0xe0U && first <= 0xefU) {
        continuation_count = 2U;
        cp = (uint32_t)(first & 0x0fU);
        if (first == 0xe0U) second_min = 0xa0U;
        if (first == 0xedU) second_max = 0x9fU;
    } else if (first >= 0xf0U && first <= 0xf4U) {
        continuation_count = 3U;
        cp = (uint32_t)(first & 0x07U);
        if (first == 0xf0U) second_min = 0x90U;
        if (first == 0xf4U) second_max = 0x8fU;
    } else {
        return fail(sc, "invalid UTF-8 leading byte");
    }
    if (continuation_count > sc->len - sc->pos)
        return fail(sc, "truncated UTF-8 sequence");
    for (size_t i = 0U; i < continuation_count; i++) {
        unsigned char byte = (unsigned char)sc->s[sc->pos++];
        unsigned char min = i == 0U ? second_min : 0x80U;
        unsigned char max = i == 0U ? second_max : 0xbfU;
        if (byte < min || byte > max)
            return fail(sc, "invalid UTF-8 continuation byte");
        cp = (cp << 6) | (uint32_t)(byte & 0x3fU);
    }
    *out = cp;
    return true;
}

static bool append_utf8(char **buf, size_t *len, size_t *cap, uint32_t cp,
                        struct scanner *sc) {
    if (cp == 0U) return fail(sc, "embedded NUL in string");
    unsigned char bytes[4];
    size_t n = 0;
    if (cp <= 0x7fU) {
        bytes[n++] = (unsigned char)cp;
    } else if (cp <= 0x7ffU) {
        bytes[n++] = (unsigned char)(0xc0U | (cp >> 6));
        bytes[n++] = (unsigned char)(0x80U | (cp & 0x3fU));
    } else if (cp <= 0xffffU) {
        bytes[n++] = (unsigned char)(0xe0U | (cp >> 12));
        bytes[n++] = (unsigned char)(0x80U | ((cp >> 6) & 0x3fU));
        bytes[n++] = (unsigned char)(0x80U | (cp & 0x3fU));
    } else if (cp <= 0x10ffffU) {
        bytes[n++] = (unsigned char)(0xf0U | (cp >> 18));
        bytes[n++] = (unsigned char)(0x80U | ((cp >> 12) & 0x3fU));
        bytes[n++] = (unsigned char)(0x80U | ((cp >> 6) & 0x3fU));
        bytes[n++] = (unsigned char)(0x80U | (cp & 0x3fU));
    } else {
        return fail(sc, "unicode code point out of range");
    }
    if (*len + n + 1 > *cap) {
        size_t new_cap = *cap == 0 ? 32 : *cap * 2;
        while (new_cap < *len + n + 1) new_cap *= 2;
        char *new_buf = realloc(*buf, new_cap);
        if (new_buf == NULL) return fail(sc, "out of memory");
        *buf = new_buf;
        *cap = new_cap;
    }
    memcpy(*buf + *len, bytes, n);
    *len += n;
    (*buf)[*len] = '\0';
    return true;
}

static bool parse_string(struct scanner *sc, char **decoded) {
    if (sc->pos >= sc->len || sc->s[sc->pos] != '"') {
        return fail(sc, "expected string");
    }
    sc->pos++;
    char *buf = NULL;
    size_t len = 0, cap = 0;
    while (sc->pos < sc->len) {
        unsigned char c = (unsigned char)sc->s[sc->pos++];
        if (c == '"') {
            if (buf == NULL) {
                buf = calloc(1, 1);
                if (buf == NULL) return fail(sc, "out of memory");
            }
            *decoded = buf;
            return true;
        }
        if (c < 0x20U) {
            free(buf);
            return fail(sc, "control character in string");
        }
        uint32_t cp = c;
        if (c >= 0x80U) {
            if (!decode_utf8(sc, c, &cp)) { free(buf); return false; }
        } else if (c == '\\') {
            if (sc->pos >= sc->len) {
                free(buf);
                return fail(sc, "truncated escape");
            }
            char e = sc->s[sc->pos++];
            switch (e) {
                case '"': cp = '"'; break;
                case '\\': cp = '\\'; break;
                case '/': cp = '/'; break;
                case 'b': cp = '\b'; break;
                case 'f': cp = '\f'; break;
                case 'n': cp = '\n'; break;
                case 'r': cp = '\r'; break;
                case 't': cp = '\t'; break;
                case 'u': {
                    if (!hex4(sc, &cp)) { free(buf); return false; }
                    if (cp >= 0xd800U && cp <= 0xdbffU) {
                        if (sc->len - sc->pos < 6 || sc->s[sc->pos] != '\\' ||
                            sc->s[sc->pos + 1] != 'u') {
                            free(buf);
                            return fail(sc, "missing low surrogate");
                        }
                        sc->pos += 2;
                        uint32_t low = 0;
                        if (!hex4(sc, &low)) { free(buf); return false; }
                        if (low < 0xdc00U || low > 0xdfffU) {
                            free(buf);
                            return fail(sc, "invalid low surrogate");
                        }
                        cp = 0x10000U + ((cp - 0xd800U) << 10) + (low - 0xdc00U);
                    } else if (cp >= 0xdc00U && cp <= 0xdfffU) {
                        free(buf);
                        return fail(sc, "unpaired low surrogate");
                    }
                    break;
                }
                default:
                    free(buf);
                    return fail(sc, "invalid escape");
            }
        }
        if (!append_utf8(&buf, &len, &cap, cp, sc)) {
            free(buf);
            return false;
        }
    }
    free(buf);
    return fail(sc, "unterminated string");
}

static bool parse_value(struct scanner *sc);

static bool parse_array(struct scanner *sc) {
    sc->pos++;
    skip_ws(sc);
    if (sc->pos < sc->len && sc->s[sc->pos] == ']') {
        sc->pos++;
        return true;
    }
    for (;;) {
        if (!parse_value(sc)) return false;
        skip_ws(sc);
        if (sc->pos >= sc->len) return fail(sc, "unterminated array");
        char c = sc->s[sc->pos++];
        if (c == ']') return true;
        if (c != ',') return fail(sc, "expected comma in array");
        skip_ws(sc);
    }
}

static int string_ptr_compare(const void *a, const void *b) {
    const char *const *sa = a;
    const char *const *sb = b;
    return strcmp(*sa, *sb);
}

static bool object_keys_are_unique(struct scanner *sc, char **keys, size_t count) {
    if (count < 2U) return true;
    qsort(keys, count, sizeof(*keys), string_ptr_compare);
    for (size_t i = 1U; i < count; i++) {
        if (strcmp(keys[i - 1U], keys[i]) == 0) {
            vane_error_set(sc->err,
                             "invalid JSON at byte %zu: duplicate key '%s'",
                             sc->pos, keys[i]);
            return false;
        }
    }
    return true;
}

static bool parse_object(struct scanner *sc) {
    sc->pos++;
    char **keys = NULL;
    size_t key_count = 0, key_cap = 0;
    skip_ws(sc);
    if (sc->pos < sc->len && sc->s[sc->pos] == '}') {
        sc->pos++;
        return true;
    }
    for (;;) {
        char *key = NULL;
        if (!parse_string(sc, &key)) goto error;
        if (key_count == key_cap) {
            size_t new_cap = key_cap == 0 ? 8 : key_cap * 2;
            char **new_keys = realloc(keys, new_cap * sizeof(*new_keys));
            if (new_keys == NULL) {
                free(key);
                (void)fail(sc, "out of memory");
                goto error;
            }
            keys = new_keys;
            key_cap = new_cap;
        }
        keys[key_count++] = key;
        skip_ws(sc);
        if (sc->pos >= sc->len || sc->s[sc->pos++] != ':') {
            (void)fail(sc, "expected colon after object key");
            goto error;
        }
        if (!parse_value(sc)) goto error;
        skip_ws(sc);
        if (sc->pos >= sc->len) {
            (void)fail(sc, "unterminated object");
            goto error;
        }
        char c = sc->s[sc->pos++];
        if (c == '}') {
            bool unique = object_keys_are_unique(sc, keys, key_count);
            for (size_t i = 0; i < key_count; i++) free(keys[i]);
            free(keys);
            return unique;
        }
        if (c != ',') {
            (void)fail(sc, "expected comma in object");
            goto error;
        }
        skip_ws(sc);
    }
error:
    for (size_t i = 0; i < key_count; i++) free(keys[i]);
    free(keys);
    return false;
}

static bool parse_number(struct scanner *sc) {
    size_t start = sc->pos;
    if (sc->s[sc->pos] == '-') sc->pos++;
    if (sc->pos >= sc->len) return fail(sc, "truncated number");
    if (sc->s[sc->pos] == '0') {
        sc->pos++;
        if (sc->pos < sc->len && isdigit((unsigned char)sc->s[sc->pos]))
            return fail(sc, "leading zero in number");
    } else if (sc->s[sc->pos] >= '1' && sc->s[sc->pos] <= '9') {
        while (sc->pos < sc->len && isdigit((unsigned char)sc->s[sc->pos])) sc->pos++;
    } else {
        return fail(sc, "invalid number");
    }
    if (sc->pos < sc->len && sc->s[sc->pos] == '.') {
        sc->pos++;
        if (sc->pos >= sc->len || !isdigit((unsigned char)sc->s[sc->pos]))
            return fail(sc, "invalid fraction");
        while (sc->pos < sc->len && isdigit((unsigned char)sc->s[sc->pos])) sc->pos++;
    }
    if (sc->pos < sc->len && (sc->s[sc->pos] == 'e' || sc->s[sc->pos] == 'E')) {
        sc->pos++;
        if (sc->pos < sc->len && (sc->s[sc->pos] == '+' || sc->s[sc->pos] == '-')) sc->pos++;
        if (sc->pos >= sc->len || !isdigit((unsigned char)sc->s[sc->pos]))
            return fail(sc, "invalid exponent");
        while (sc->pos < sc->len && isdigit((unsigned char)sc->s[sc->pos])) sc->pos++;
    }
    return sc->pos > start;
}

static bool parse_literal(struct scanner *sc, const char *literal) {
    size_t n = strlen(literal);
    if (sc->len - sc->pos < n || memcmp(sc->s + sc->pos, literal, n) != 0)
        return fail(sc, "invalid literal");
    sc->pos += n;
    return true;
}

static bool parse_value(struct scanner *sc) {
    skip_ws(sc);
    if (sc->pos >= sc->len) return fail(sc, "missing value");
    char c = sc->s[sc->pos];
    if (c == '{' || c == '[') {
        if (sc->depth >= VANE_JSON_MAX_DEPTH)
            return fail(sc, "nesting depth exceeds limit");
        sc->depth++;
        bool ok = c == '{' ? parse_object(sc) : parse_array(sc);
        sc->depth--;
        return ok;
    }
    if (c == '"') {
        char *tmp = NULL;
        bool ok = parse_string(sc, &tmp);
        free(tmp);
        return ok;
    }
    if (c == 't') return parse_literal(sc, "true");
    if (c == 'f') return parse_literal(sc, "false");
    if (c == 'n') return parse_literal(sc, "null");
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number(sc);
    return fail(sc, "unexpected token");
}

bool vane_json_validate_strict(const char *data, size_t len,
                                 struct vane_error *err) {
    struct scanner sc = {.s = data, .len = len, .pos = 0, .err = err};
    if (!parse_value(&sc)) return false;
    skip_ws(&sc);
    if (sc.pos != sc.len) return fail(&sc, "trailing data");
    return true;
}
