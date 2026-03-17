#ifndef URANDOM_H__
#define URANDOM_H__

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>

inline void urandom_fill(void *buf, size_t nbytes) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    abort();
  size_t total = 0;
  while (total < nbytes) {
    ssize_t n = read(fd, static_cast<char *>(buf) + total, nbytes - total);
    if (n <= 0) {
      close(fd);
      abort();
    }
    total += n;
  }
  close(fd);
}

inline uint32_t urandom_uint32() {
  uint32_t v;
  urandom_fill(&v, sizeof(v));
  return v;
}

inline uint64_t urandom_uint64() {
  uint64_t v;
  urandom_fill(&v, sizeof(v));
  return v;
}

#endif // URANDOM_H__
