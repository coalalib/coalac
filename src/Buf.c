#define _GNU_SOURCE	/* vasprintf */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <coala/Buf.h>
#include <coala/Mem.h>

/*
 * @file
 * Простейшая реализация буфера.
 */

/*
 * Дескриптор буфера.
 */
struct Buf_Handle {
	size_t size;
	void *data;
};

/*
 * Создаёт новый буфер и возвращает его дескриптор.
 *
 * @return дескриптор на буфер либо NULL при ошибках (см. errno).
 */
struct Buf_Handle *Buf(void)
{
	struct Buf_Handle *h;

	return Mem_calloc(1, sizeof *h);
}

/*
 * Освобождает буфер по дескриптору.
 *
 * @param h	дескриптор буфера
 */
void Buf_Free(struct Buf_Handle *h)
{
	if (h == NULL)
		return;

	Mem_free(h->data);
	Mem_free(h);
}

/*
 * Очищает буфер по дескриптору.
 *
 * @param h	дескриптор буфера
 */
void Buf_Clear(struct Buf_Handle *h)
{
	if (h == NULL)
		return;

	Mem_free(h->data);
	h->data = NULL;
	h->size = 0;
}

/*
 * Добавляет данные в буфер с заданным дескриптором.
 *
 * @param h	дескриптор буфера
 * @param data	указатель на данные
 * @param size	размера данных
 *
 * @return 0 при успешном завершении и -1 при ошибке (см. errno).
 */
int Buf_Add(struct Buf_Handle *h, const void *data, size_t size)
{
	void *m;

	if (h == NULL || data == NULL || !size) {
		errno = EINVAL;
		return -1;
	}

	m = Mem_realloc(h->data, h->size + size);
	if (m == NULL)
		return -1;

	memcpy(m + h->size, data, size);

	h->size += size;
	h->data = m;

	return 0;
}

/*
 * Добавляет заданный символ в буфер с заданным дескриптором.
 *
 * @param h	дескриптор буфера
 * @param c	символ
 *
 * @return 0 при успешном завершении либо -1 при ошибке (см. errno).
 */
int Buf_AddCh(struct Buf_Handle *h, char c)
{
	return Buf_Add(h, &c, sizeof c);
}

/*
 * Добавляет строку в буфер с заданным дескриптором.
 *
 * @param h	дескриптор буфера
 * @param s	указатель на строку
 *
 * @return 0 при успешном завершении либо -1 при ошибке (см. errno).
 */
int Buf_AddStr(struct Buf_Handle *h, const char *s)
{
	if (s == NULL) {
		errno = EINVAL;
		return -1;
	}

	return Buf_Add(h, s, strlen(s));
}

/*
 * Добавляет форматированную строку в буфер с заданным дескриптором.
 *
 * @param h	дескриптор буфера
 * @param fmt	строка формата
 *
 * @return 0 при успешном завершении либо -1 при ошибке (см. errno).
 */
int Buf_AddFormatStr(struct Buf_Handle *h, const char *fmt, ...)
{
	char *s;
	int ret;
	va_list ap;

	if (fmt == NULL) {
		errno = EINVAL;
		return -1;
	}

	va_start(ap, fmt);
	ret = vasprintf(&s, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}

	ret = Buf_AddStr(h, s);
	Mem_free(s);

	return ret;
}

/*
 * Возвращает данные буфера и его размер по дескриптору.
 *
 * @param h	дескриптор буфера
 * @param size	указатель для размещения размера либо NULL
 * @param alloc	возвратить данные в динамической памяти?
 *
 * @return указатель на данные при успешном завершении либо NULL (см. errno).
 */
void *Buf_GetData(struct Buf_Handle *h, size_t *size, bool alloc)
{
	void *p;
	size_t s;

	if (h == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((p = h->data) == NULL) {
		errno = ENODATA;
		return NULL;
	}

	s = h->size;

	if (alloc) {
		void *q = Mem_malloc(s);
		if (q == NULL)
			return NULL;

		memcpy(q, p, s);
		p = q;
	}

	if (size)
		*size = s;

	return p;
}

/*
 * Печатает содержимое буфера в заданный файловый поток.
 *
 * @param h	дескриптор буфера
 * @param fp	файловый поток
 *
 * @return 0 при успешном завершении и -1 при ошибке (см. errno).
 */
int Buf_Print(struct Buf_Handle *h, FILE *fp)
{
	size_t i, s;
	unsigned char *d;

	if (h == NULL || fp == NULL) {
		errno = EINVAL;
		return -1;
	}

	d = Buf_GetData(h, &s, false);
	if (d == NULL) {
		if (errno == ENODATA) {
			fprintf(fp, "buf is empty\n");
			return 0;
		} else {
			return -1;
		}
	}

	for (i = 0; i < s; i++)
		fprintf(fp, "0x%x:\t0x%02hhx %c\n", (unsigned) i, d[i],
			(char) d[i]);

	return 0;
}
