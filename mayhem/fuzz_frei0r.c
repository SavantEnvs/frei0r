/*
 * libFuzzer harness for the frei0r plugin ABI, driven through upstream's static bundle registry
 * (include/frei0r/bundle.h): every bundled plugin is linked in-process, so ASan/UBSan see the
 * plugin code itself and no dlopen is involved.
 *
 * One source, compiled once per plugin kind (-DFUZZ_KIND=<F0R_PLUGIN_TYPE_*>); with
 * -DFUZZ_ONLY_PLUGIN="id" it fuzzes a single plugin instead (used for curves' string parser).
 *
 * Input layout (all fields wrap; a short input reads as zeros):
 *   [0]      plugin selector (index among the plugins of this kind; ignored with FUZZ_ONLY_PLUGIN)
 *   [1] [2]  width, height  -> 8 * (1 + b % 12)  (frei0r requires multiples of 8)
 *   [3]      frame count    -> 1 + b % 3
 *   [4]      timestamp      -> b / 8.0
 *   then one parameter block per frame (BOOL 1 byte, DOUBLE 2 bytes, COLOR 3, POSITION 4,
 *   STRING = bytes up to a NUL), then the rest of the input is the pixel data, cycled over every
 *   input frame.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frei0r.h"
#include "frei0r/bundle.h"

#ifndef FUZZ_KIND
#define FUZZ_KIND F0R_PLUGIN_TYPE_FILTER
#endif

#define MAX_PLUGINS 256
#define MAX_STRING 512

static const f0r_plugin_descriptor_t *g_plugins[MAX_PLUGINS];
static size_t g_nplugins;

typedef struct {
  const uint8_t *p;
  size_t n;
} reader_t;

static uint8_t rd8(reader_t *r) {
  if (r->n == 0) return 0;
  r->n--;
  return *r->p++;
}

static double rd_unit16(reader_t *r) {
  unsigned v = rd8(r);
  v = (v << 8) | rd8(r);
  return v / 65535.0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  size_t count = f0r_bundle_plugin_count();
  for (size_t i = 0; i < count && g_nplugins < MAX_PLUGINS; i++) {
    const f0r_plugin_descriptor_t *d = f0r_bundle_plugin_by_index(i);
    if (!d || d->descriptor_size < F0R_PLUGIN_DESCRIPTOR_SIZE) continue;
    /* f0r_init's return value is not uniform across plugins (some return 0 on success), hosts ignore it */
    d->init();
    f0r_plugin_info_t info;
    memset(&info, 0, sizeof info);
    d->get_plugin_info(&info);
    d->deinit();
#ifdef FUZZ_ONLY_PLUGIN
    if (strcmp(d->id, FUZZ_ONLY_PLUGIN) == 0) g_plugins[g_nplugins++] = d;
#else
    if (info.plugin_type == FUZZ_KIND) g_plugins[g_nplugins++] = d;
#endif
  }
  if (g_nplugins == 0) {
    fprintf(stderr, "no bundled plugin of the requested kind\n");
    abort();
  }
  return 0;
}

static void set_params(const f0r_plugin_descriptor_t *d, f0r_instance_t inst,
                       int nparams, reader_t *r) {
  for (int i = 0; i < nparams; i++) {
    f0r_param_info_t pi;
    memset(&pi, 0, sizeof pi);
    d->get_param_info(&pi, i);
    switch (pi.type) {
      case F0R_PARAM_BOOL: {
        double v = rd8(r) & 1;
        d->set_param_value(inst, &v, i);
        break;
      }
      case F0R_PARAM_DOUBLE: {
        double v = rd_unit16(r);
        d->set_param_value(inst, &v, i);
        break;
      }
      case F0R_PARAM_COLOR: {
        f0r_param_color_t c;
        c.r = rd8(r) / 255.0f;
        c.g = rd8(r) / 255.0f;
        c.b = rd8(r) / 255.0f;
        d->set_param_value(inst, &c, i);
        break;
      }
      case F0R_PARAM_POSITION: {
        f0r_param_position_t pos;
        pos.x = rd_unit16(r);
        pos.y = rd_unit16(r);
        d->set_param_value(inst, &pos, i);
        break;
      }
      case F0R_PARAM_STRING: {
        char buf[MAX_STRING + 1];
        size_t len = 0;
        while (r->n > 0 && len < MAX_STRING) {
          uint8_t c = rd8(r);
          if (c == 0) break;
          buf[len++] = (char)c;
        }
        buf[len] = 0;
        char *s = buf;
        d->set_param_value(inst, &s, i);
        break;
      }
      default:
        break;
    }
  }
}

static void get_params(const f0r_plugin_descriptor_t *d, f0r_instance_t inst,
                       int nparams) {
  for (int i = 0; i < nparams; i++) {
    f0r_param_info_t pi;
    memset(&pi, 0, sizeof pi);
    d->get_param_info(&pi, i);
    union {
      double d;
      f0r_param_color_t c;
      f0r_param_position_t p;
      char *s;
    } out;
    memset(&out, 0, sizeof out);
    if (pi.type <= F0R_PARAM_STRING) d->get_param_value(inst, &out, i);
  }
}

static uint32_t *alloc_frame(size_t pixels, reader_t *pix) {
  void *mem = NULL;
  size_t bytes = pixels * 4;
  if (posix_memalign(&mem, 16, bytes) != 0) abort();
  uint8_t *b = mem;
  for (size_t i = 0; i < bytes; i++) b[i] = rd8(pix);
  return mem;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  reader_t r = {data, size};
#ifdef FUZZ_ONLY_PLUGIN
  const f0r_plugin_descriptor_t *d = g_plugins[0];
#else
  const f0r_plugin_descriptor_t *d = g_plugins[rd8(&r) % g_nplugins];
#endif
  unsigned width = 8 * (1 + rd8(&r) % 12);
  unsigned height = 8 * (1 + rd8(&r) % 12);
  unsigned nframes = 1 + rd8(&r) % 3;
  double time = rd8(&r) / 8.0;

  d->init();
  f0r_plugin_info_t info;
  memset(&info, 0, sizeof info);
  d->get_plugin_info(&info);
  int nparams = info.num_params;
  if (nparams < 0 || nparams > 64) nparams = 0;

  f0r_instance_t inst = d->construct(width, height);
  if (!inst) {
    d->deinit();
    return 0;
  }

  /* One parameter block per frame; the pixels follow the last block. The first pass only measures
     the blocks (and sets the initial values), the replay below re-reads them frame by frame. */
  reader_t pix = r;
  for (unsigned f = 0; f < nframes; f++) set_params(d, inst, nparams, &pix);
  size_t consumed = r.n - pix.n;
  reader_t params = {r.p, consumed};
  reader_t pixels = pix;
  if (pixels.n == 0) pixels = (reader_t){(const uint8_t *)"\x00", 1};

  size_t npix = (size_t)width * height;
  int ninputs = 0;
  if (FUZZ_KIND == F0R_PLUGIN_TYPE_FILTER) ninputs = 1;
  if (FUZZ_KIND == F0R_PLUGIN_TYPE_MIXER2) ninputs = 2;
  if (FUZZ_KIND == F0R_PLUGIN_TYPE_MIXER3) ninputs = 3;
  uint32_t *in[3] = {NULL, NULL, NULL};
  for (int i = 0; i < ninputs; i++) {
    /* cycle the pixel bytes so a short input still fills every frame */
    reader_t cyc = pixels;
    size_t bytes = npix * 4;
    void *mem = NULL;
    if (posix_memalign(&mem, 16, bytes) != 0) abort();
    uint8_t *b = mem;
    for (size_t k = 0; k < bytes; k++) {
      if (cyc.n == 0) cyc = pixels;
      b[k] = rd8(&cyc);
    }
    in[i] = mem;
  }
  uint32_t *out = alloc_frame(npix, &(reader_t){NULL, 0});

  /* replay the parameter blocks, one per frame, updating after each */
  for (unsigned f = 0; f < nframes; f++) {
    set_params(d, inst, nparams, &params);
    if (FUZZ_KIND == F0R_PLUGIN_TYPE_FILTER || FUZZ_KIND == F0R_PLUGIN_TYPE_SOURCE) {
      if (d->update) d->update(inst, time + f * 0.04, in[0], out);
    } else if (d->update2) {
      d->update2(inst, time + f * 0.04, in[0], in[1], in[2], out);
    }
    get_params(d, inst, nparams);
  }

  for (int i = 0; i < ninputs; i++) free(in[i]);
  free(out);
  d->destruct(inst);
  d->deinit();
  return 0;
}
