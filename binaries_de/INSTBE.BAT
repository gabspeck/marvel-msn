@echo off
:cdrive
move /y %1 c:\progra~1\themic~1\bsen.exe
if errorlevel 1 goto ddrive
c:\progra~1\themic~1\bsen.exe /o c:\progra~1\themic~1
erase c:\progra~1\themic~1\bsen.exe
goto done

:ddrive
move /y %1 d:\progra~1\themic~1\bsen.exe
if errorlevel 1 goto askdrive
d:\progra~1\themic~1\bsen.exe /o d:\progra~1\themic~1
erase d:\progra~1\themic~1\bsen.exe
goto done

:askdrive
set msnins=nul
echo.
echo ******************************************************************
echo * Das Laufwerk mit dem Windows-Verzeichnis wurde nicht gefunden. *
echo ******************************************************************
echo * Geben Sie den Buchstaben des Laufwerks ein, in dem Windows     *
echo * installiert ist.                                               *
echo ******************************************************************
choice /c:cdefghijklmnopqrstuvwxyz
if errorlevel 03 set msnins=e
if errorlevel 04 set msnins=f
if errorlevel 05 set msnins=g
if errorlevel 06 set msnins=h
if errorlevel 07 set msnins=i
if errorlevel 08 set msnins=j
if errorlevel 09 set msnins=k
if errorlevel 10 set msnins=l
if errorlevel 11 set msnins=m
if errorlevel 12 set msnins=n
if errorlevel 13 set msnins=o
if errorlevel 14 set msnins=p
if errorlevel 15 set msnins=q
if errorlevel 16 set msnins=r
if errorlevel 17 set msnins=s
if errorlevel 18 set msnins=t
if errorlevel 19 set msnins=u
if errorlevel 20 set msnins=v
if errorlevel 21 set msnins=w
if errorlevel 22 set msnins=x
if errorlevel 23 set msnins=y
if errorlevel 24 set msnins=z
if errorlevel 25 set msnins=nul
if "%msnins%"=="nul" goto fail

:tryagain
move /y %1 %msnins%:\progra~1\themic~1\bsen.exe
if errorlevel 1 goto fail
%msnins%:\progra~1\themic~1\bsen.exe /o %msnins%:\progra~1\themic~1
erase %msnins%:\progra~1\themic~1\bsen.exe
goto done

:fail
erase %1
echo.
echo *****************************************************
echo *          Fehler bei der Installation              *
echo *                                                   *
echo *     Weitere Informationen finden Sie unter        * 
echo *     "Fehlerbehebung" im Mitglieder-Service.       *
echo *                                                   *
echo * Sie k”nnen dieses MS-DOS-Fenster jetzt schlieáen. *
echo *****************************************************
echo.
goto end

:done
echo.
echo **********************************************
echo *      Die Installation ist beendet.         *
echo *                                            *
echo * Schlieáen Sie jetzt dieses MS-DOS-Fenster. *
echo **********************************************
echo.

:end
