#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=x86_64-w64-mingw32-gcc
CCC=x86_64-w64-mingw32-g++
CXX=x86_64-w64-mingw32-g++
FC=gfortran
AS=x86_64-w64-mingw32-as

# Macros
CND_PLATFORM=Cygwin-Windows
CND_DLIB_EXT=dll
CND_CONF=Release
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/_ext/d914b006/winselfcert.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/winselfcert.${CND_DLIB_EXT}

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/winselfcert.${CND_DLIB_EXT}: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.c} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/winselfcert.${CND_DLIB_EXT} ${OBJECTFILES} ${LDLIBSOPTIONS} -lcrypt32 -shared

${OBJECTDIR}/_ext/d914b006/winselfcert.o: /cygdrive/C/Data/Documents/NetBeansProjects/winselfcert/winselfcertdll/winselfcert.c
	${MKDIR} -p ${OBJECTDIR}/_ext/d914b006
	${RM} "$@.d"
	$(COMPILE.c) -O2 -I../winselfcert/headers -I/cygdrive/C/Program\ Files/Java/jdk1.8.0_152/include -I/cygdrive/C/Program\ Files/Java/jdk1.8.0_152/include/win32  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/d914b006/winselfcert.o /cygdrive/C/Data/Documents/NetBeansProjects/winselfcert/winselfcertdll/winselfcert.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
