#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <wiringPi.h> // This module needs the wiringPi library

#include <stdlib.h>
#include <time.h>
#include <re.h>
#include <baresip.h>

// Use GPIO Pin 17, which is Pin 0 for wiringPi library
#define BUTTON_PIN 0


/**
 * Return the current User-Agent in focus
 * Taken from menu.c
 * @return Current User-Agent
 */

static struct ua *uag_cur(void)
{
	return uag_current();
}


static void ButtonPressedInterruption(void) {

	int err = 0;

	err = ua_connect(uag_cur(), NULL, NULL, "100", NULL, VIDMODE_ON);

}

static int raspgpioinput_init(void) {

	// TO DO : Retrieving config from the config fime
	int err;

  // Seting up the Wiring Pi Library
  if (wiringPiSetup () < 0) {
      fprintf (stderr, "Unable to setup wiringPi: %s\n", strerror (errno));
      return 1;
  }

  // Attaching the interruption
  if ( wiringPiISR (BUTTON_PIN, INT_EDGE_FALLING, &ButtonPressedInterruption) < 0 ) {
      fprintf (stderr, "Unable to setup ISR: %s\n", strerror (errno));
      return 1;
  }

  while ( 1 ) {
    // Lopp
  }

  return 0;
}

static int raspgpioinput_close(void)
{
	raspgpioinput = mem_deref(raspgpioinput);
 	return 0;
}

EXPORT_SYM const struct mod_export DECL_EXPORTS(raspgpioinput) = {
	"raspgpioinput",
	"ui",
	raspgpioinput_init,
	raspgpioinput_close
};

