/*
 * Known-answer probe for the bundled frei0r plugins (the behavioral oracle behind mayhem/test.sh).
 *
 * Every plugin of the static bundle is driven through the real frei0r ABI with fixed parameters and
 * fixed input frames; the output frames are hashed and printed one line per plugin. test.sh diffs
 * that text against mayhem/kat.expected, so a build whose plugins compute something else (or a
 * binary that just exits 0) fails. A few plugins are additionally checked against values that are
 * known by construction (invert, addition, ...), printed as `check <name> ok|FAIL`.
 *
 *   kat            print the known-answer table
 *   kat --list     print "<kind> <index-within-kind> <id>" for every plugin (used to make seeds)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "frei0r.h"
#include "frei0r/bundle.h"

#define W 32
#define H 16
#define NPIX (W * H)

static uint32_t lcg_state;
static uint32_t lcg(void) {
  lcg_state = lcg_state * 1664525u + 1013904223u;
  return lcg_state >> 8;
}

static void fill_frame(uint32_t *f, uint32_t seed) {
  lcg_state = seed;
  for (int y = 0; y < H; y++)
    for (int x = 0; x < W; x++) {
      uint32_t r = (x * 8 + (lcg() & 15)) & 255;
      uint32_t g = (y * 16 + (lcg() & 15)) & 255;
      uint32_t b = ((x + y) * 5 + (lcg() & 31)) & 255;
      uint32_t a = 255 - ((x * y) & 63);
      f[y * W + x] = r | (g << 8) | (b << 16) | (a << 24);
    }
}

static uint64_t fnv(const void *p, size_t n) {
  const uint8_t *b = p;
  uint64_t h = 1469598103934665603ull;
  for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 1099511628211ull;
  return h;
}

static void set_params(const f0r_plugin_descriptor_t *d, f0r_instance_t inst, int n) {
  for (int i = 0; i < n; i++) {
    f0r_param_info_t pi;
    memset(&pi, 0, sizeof pi);
    d->get_param_info(&pi, i);
    double v = 0.25 + 0.5 * ((i * 37 % 10) / 10.0);
    switch (pi.type) {
      case F0R_PARAM_BOOL:
        v = i & 1;
        d->set_param_value(inst, &v, i);
        break;
      case F0R_PARAM_DOUBLE:
        d->set_param_value(inst, &v, i);
        break;
      case F0R_PARAM_COLOR: {
        f0r_param_color_t c = {(float)v, (float)(1.0 - v), 0.5f};
        d->set_param_value(inst, &c, i);
        break;
      }
      case F0R_PARAM_POSITION: {
        f0r_param_position_t p = {v, 1.0 - v};
        d->set_param_value(inst, &p, i);
        break;
      }
      case F0R_PARAM_STRING: {
        char *s = strcmp(d->id, "colortap") == 0 ? (char *)"sepia" : (char *)"";
        d->set_param_value(inst, &s, i);
        break;
      }
    }
  }
}

/* Runs one plugin for two frames; returns the output hash, or 0 if it could not be constructed. */
static uint64_t run_plugin(const f0r_plugin_descriptor_t *d, int type, uint32_t *out) {
  static uint32_t in[3][NPIX] __attribute__((aligned(16)));
  for (int i = 0; i < 3; i++) fill_frame(in[i], 1000 + i);
  memset(out, 0, NPIX * 4);
  d->init();
  f0r_plugin_info_t info;
  memset(&info, 0, sizeof info);
  d->get_plugin_info(&info);
  f0r_instance_t inst = d->construct(W, H);
  if (!inst) {
    d->deinit();
    return 0;
  }
  set_params(d, inst, info.num_params);
  uint64_t h = 1469598103934665603ull;
  for (int f = 0; f < 2; f++) {
    double t = f * 0.04;
    if (type == F0R_PLUGIN_TYPE_FILTER)
      d->update(inst, t, in[0], out);
    else if (type == F0R_PLUGIN_TYPE_SOURCE)
      d->update(inst, t, NULL, out);
    else
      d->update2(inst, t, in[0], in[1], in[2], out);
    h = (h ^ fnv(out, NPIX * 4)) * 1099511628211ull;
  }
  d->destruct(inst);
  d->deinit();
  return h;
}

/* Plugins left out of the answer table: output depends on rand()/uninitialised heap (it changes
   under MALLOC_PERTURB_), or a crash on these fixed inputs (the fuzzers' job). `kat --discover`. */
static const char *const skip_ids[] = {
    "3dflippo", "cluster", "delaygrab", "filmgrain", "gateweave", "glitch0r", "partik0l", "pixs0r",
    "plasma", "rgbnoise", "test_pat_I", "water", NULL};

static int skipped(const char *id) {
  for (int i = 0; skip_ids[i]; i++)
    if (strcmp(skip_ids[i], id) == 0) return 1;
  return 0;
}

/* Runs one plugin in a child so a crash is reported instead of killing the probe. */
static uint64_t run_isolated(const f0r_plugin_descriptor_t *d, int type, int *status) {
  static uint32_t out[NPIX] __attribute__((aligned(16)));
  int fds[2];
  if (pipe(fds) != 0) exit(2);
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    close(fds[0]);
    uint64_t h = run_plugin(d, type, out);
    if (write(fds[1], &h, sizeof h) != (ssize_t)sizeof h) _exit(3);
    _exit(0);
  }
  close(fds[1]);
  uint64_t h = 0;
  ssize_t got = read(fds[0], &h, sizeof h);
  close(fds[0]);
  int st = 0;
  waitpid(pid, &st, 0);
  *status = (WIFEXITED(st) && WEXITSTATUS(st) == 0 && got == (ssize_t)sizeof h) ? 0 : 1;
  return h;
}

static const f0r_plugin_descriptor_t *find(const char *id) {
  return f0r_bundle_plugin_by_id(id);
}

/* Output of a one-parameter-free filter/mixer on the standard inputs, for the by-construction checks. */
static void check_known(void) {
  static uint32_t a[NPIX] __attribute__((aligned(16))), b[NPIX] __attribute__((aligned(16))),
      out[NPIX] __attribute__((aligned(16)));
  fill_frame(a, 1000);
  fill_frame(b, 1001);
  int ok;

  const f0r_plugin_descriptor_t *d = find("invert0r");
  ok = d != NULL;
  if (ok) {
    d->init();
    f0r_instance_t i = d->construct(W, H);
    d->update(i, 0.0, a, out);
    for (int k = 0; k < NPIX; k++)
      if (out[k] != ((a[k] & 0xff000000u) | (~a[k] & 0x00ffffffu))) ok = 0;
    d->destruct(i);
    d->deinit();
  }
  printf("check invert0r_complements_rgb_keeps_alpha %s\n", ok ? "ok" : "FAIL");

  d = find("addition");
  ok = d != NULL;
  if (ok) {
    d->init();
    f0r_instance_t i = d->construct(W, H);
    d->update2(i, 0.0, a, b, NULL, out);
    for (int k = 0; k < NPIX; k++)
      for (int c = 0; c < 3; c++) {
        unsigned s = ((a[k] >> (8 * c)) & 255) + ((b[k] >> (8 * c)) & 255);
        if (s > 255) s = 255;
        if (((out[k] >> (8 * c)) & 255) != s) ok = 0;
      }
    d->destruct(i);
    d->deinit();
  }
  printf("check addition_saturates_per_channel %s\n", ok ? "ok" : "FAIL");

  d = find("bw0r");
  ok = d != NULL;
  if (ok) {
    d->init();
    f0r_instance_t i = d->construct(W, H);
    d->update(i, 0.0, a, out);
    for (int k = 0; k < NPIX; k++) {
      uint32_t r = out[k] & 255, g = (out[k] >> 8) & 255, bl = (out[k] >> 16) & 255;
      if (r != g || g != bl) ok = 0;
    }
    d->destruct(i);
    d->deinit();
  }
  printf("check bw0r_output_is_gray %s\n", ok ? "ok" : "FAIL");

  d = find("onecol0r");
  ok = d != NULL;
  if (ok) {
    d->init();
    f0r_instance_t i = d->construct(W, H);
    f0r_param_color_t c = {1.0f, 0.0f, 0.0f};
    d->set_param_value(i, &c, 0);
    d->update(i, 0.0, NULL, out);
    for (int k = 0; k < NPIX; k++)
      if (out[k] != 0xffff0000u) ok = 0;
    d->destruct(i);
    d->deinit();
  }
  printf("check onecol0r_fills_requested_colour_as_bgra %s\n", ok ? "ok" : "FAIL");
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  size_t count = f0r_bundle_plugin_count();
  if (argc > 1 && strcmp(argv[1], "--list") == 0) {
    int per_kind[4] = {0, 0, 0, 0};
    for (size_t n = 0; n < count; n++) {
      const f0r_plugin_descriptor_t *d = f0r_bundle_plugin_by_index(n);
      f0r_plugin_info_t info;
      memset(&info, 0, sizeof info);
      d->init();
      d->get_plugin_info(&info);
      d->deinit();
      if (info.plugin_type >= 0 && info.plugin_type < 4)
        printf("%d %d %s\n", info.plugin_type, per_kind[info.plugin_type]++, d->id);
    }
    return 0;
  }
  int discover = argc > 1 && strcmp(argv[1], "--discover") == 0;
  printf("plugins %zu\n", count);
  for (size_t n = 0; n < count; n++) {
    const f0r_plugin_descriptor_t *d = f0r_bundle_plugin_by_index(n);
    d->init();
    f0r_plugin_info_t info;
    memset(&info, 0, sizeof info);
    d->get_plugin_info(&info);
    d->deinit();
    if (!discover && skipped(d->id)) continue;
    int status;
    uint64_t h = run_isolated(d, info.plugin_type, &status);
    if (status != 0)
      printf("kat %s type=%d params=%d CRASH\n", d->id, info.plugin_type, info.num_params);
    else
      printf("kat %s type=%d params=%d %016llx\n", d->id, info.plugin_type, info.num_params,
             (unsigned long long)h);
  }
  if (!discover) check_known();
  return 0;
}
