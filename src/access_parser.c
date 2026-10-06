#include <regex.h>
#include <stdio.h>
#include <string.h>

enum regex_pattern {
	REGEX_USERNAME = 0,
	REGEX_FINGERPRINT,
	REGEX_VALIDUSER,
	REGEX_IP_ADDR,
	REGEX_PATTERN_NUMBER
};

static struct regex_parser {
	char *pattern;
	regex_t regex;
} regex_parser[REGEX_PATTERN_NUMBER] = {
	{ .pattern = "username=([^[:space:]]+)" },
	{ .pattern = "fingerprint=([^[:space:]]+)" },
	{ .pattern = "valid_user=([^[:space:]]+)" },
	{ .pattern = "ip_addr=([^[:space:]]+)" },
};

int init_regex_parser(void)
{
	int i = 0, ret = 0;

	for (i = 0; i < REGEX_PATTERN_NUMBER; i++) {
		struct regex_parser *cur_parser = &regex_parser[i];
		regex_t *regex = &cur_parser->regex;
		char *pattern = cur_parser->pattern;

		ret = regcomp(regex, pattern, REG_EXTENDED);
		if (ret) {
			char err[256] = { 0 };
			regerror(ret, regex, err, 256); \
			fprintf(stderr, "regexec failed: %s\n", err); \
			goto out;
		}
	}

out:
	return ret;
}

static int extract_value(char *dst, char *src, int bufsize, enum regex_pattern type)
{
	int ret = 0;
	regex_t *regex = &regex_parser[type].regex;
	regmatch_t matches[2] = { 0 };
	regoff_t start = -1;
	int len = 0;

	if (!dst || !src || type >= REGEX_PATTERN_NUMBER) {
		fprintf(stderr, "%s: Invalid arg\n", __func__);
		ret = -1;
		goto out;
	}

	/* if one submatch, nmatch is two, idx 0 is for the whole string */
	ret = regexec(regex, src, 2, matches, 0);
	if (ret) {
		fprintf(stderr, "Failed to match %s for type %d\n", src, type);
		goto out;
	}

	start = matches[1].rm_so;
	len = matches[1].rm_eo - start;

	if (len < 0 || len >= bufsize) {
		ret = -1;
		fprintf(stderr, "%s: Invalid value (type %d)\n", __func__, type);
		goto out;
	}

	memcpy(dst, src + start, len);
	dst[len] = '\0';

out:
	return ret;
}

int extract_username(char *dst, char *src, int bufsize)
{
	return extract_value(dst, src, bufsize, REGEX_USERNAME);
}

int extract_fingerprint(char *dst, char *src, int bufsize)
{
	return extract_value(dst, src, bufsize, REGEX_FINGERPRINT);
}

int extract_validuser(char *dst, char *src, int bufsize)
{
	return extract_value(dst, src, bufsize, REGEX_VALIDUSER);
}

int extract_ipaddr(char *dst, char *src, int bufsize)
{
	return extract_value(dst, src, bufsize, REGEX_IP_ADDR);
}
