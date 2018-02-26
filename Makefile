#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

PROJECT_NAME := app-template

include $(IDF_PATH)/make/project.mk

tags:
	ctags -R --c++-kinds=+p --fields=+iaS --extra=+q $(IDF_PATH) .

