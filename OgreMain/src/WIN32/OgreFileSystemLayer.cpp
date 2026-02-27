/*
 -----------------------------------------------------------------------------
 This source file is part of OGRE
 (Object-oriented Graphics Rendering Engine)
 For the latest info, see http://www.ogre3d.org/
 
 Copyright (c) 2000-2014 Torus Knot Software Ltd
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 -----------------------------------------------------------------------------
 */
#include "OgreStableHeaders.h"
#include "OgreFileSystemLayer.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#if OGRE_PLATFORM == OGRE_PLATFORM_WIN32
#  include <shlobj.h>
#endif
#include <io.h>
#include <direct.h>
#include <errno.h>

namespace Ogre
{
    bool widePathToOgreString(String& dest, const WCHAR* wpath)
    {
        // need to convert to narrow (OEM or ANSI) codepage so that fstream can use it
        // properly on international systems.
#if OGRE_PLATFORM == OGRE_PLATFORM_WIN32
        // Note, that on legacy CRT versions codepage for narrow CRT file functions can be changed using
        // SetFileApisANSI/OEM, but on modern runtimes narrow pathes are always widened using ANSI codepage.
        // We suppose that on such runtimes file APIs codepage is left in default, ANSI state.
        UINT codepage = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
#elif OGRE_PLATFORM == OGRE_PLATFORM_WINRT
        // Runtime is modern, narrow calls are widened inside CRT using CP_ACP codepage.
        UINT codepage = CP_ACP;
#endif
        const int wlength = static_cast<int>(wcslen(wpath));
        const int length = WideCharToMultiByte( codepage, 0 /* Use default flags */, wpath,
                                                wlength, NULL, 0, NULL, NULL );
        if(length <= 0)
        {
            dest.clear();
            return false;
        }

        // success
        dest.resize(length);
        WideCharToMultiByte( codepage, 0 /* Use default flags */, wpath, wlength, &dest[0],
                             (int)dest.size(), NULL, NULL );
        return true;
    }

    void FileSystemLayer::getConfigPaths()
    {
#if OGRE_PLATFORM == OGRE_PLATFORM_WIN32
        // try to determine the application's path
        DWORD bufsize = 256;
        char* resolved = 0;
        do
        {
            char* buf = OGRE_ALLOC_T(char, bufsize, Ogre::MEMCATEGORY_GENERAL);
            DWORD retval = GetModuleFileName(NULL, buf, bufsize);
            if (retval == 0)
            {
                // failed
                OGRE_FREE(buf, Ogre::MEMCATEGORY_GENERAL);
                break;
            }

            if (retval < bufsize)
            {
                // operation was successful.
                resolved = buf;
            }
            else
            {
                // buffer was too small, grow buffer and try again
                OGRE_FREE(buf, Ogre::MEMCATEGORY_GENERAL);
                bufsize <<= 1;
            }
        } while (!resolved);

        Ogre::String appPath = resolved;
        if (resolved)
            OGRE_FREE(resolved, Ogre::MEMCATEGORY_GENERAL);
        if (!appPath.empty())
        {
            // need to strip the application filename from the path
            Ogre::String::size_type pos = appPath.rfind('\\');
            if (pos != Ogre::String::npos)
                appPath.erase(pos);
        }
        else
        {
            // fall back to current working dir
            appPath = ".";
        }

#elif OGRE_PLATFORM == OGRE_PLATFORM_WINRT
        Ogre::String appPath;
        if(!widePathToOgreString(appPath, Windows::ApplicationModel::Package::Current->InstalledLocation->Path->Data()))
        {
            // fallback to current working dir
            appPath = ".";
        }
#endif

        // use application path as config search path
        mConfigPaths.push_back(appPath + '\\');
    }
    //---------------------------------------------------------------------
    void FileSystemLayer::prepareUserHome(const Ogre::String& subdir)
    {
        // fill mHomePath
#if OGRE_PLATFORM == OGRE_PLATFORM_WIN32
        WCHAR wpath[MAX_PATH];

        /////////////////////////////////////////////////////////////

        // If Controlled Folder Access is enabled, the Documents folder is blocked by default.
        // To avoid the player having to explicitly allow the access, fall-back to APP_DATA instead.
        //
        // But we want to make sure that we continue to use the APP_DATA even if they then give access,
        // otherwise settings/saves would be read from the wrong folder.
        //
        // So first see if there is already the APP_DATA sub folder we are looking for.
        //
        // Don't pass the CSIDL_FLAG_CREATE, so we don't show the access warning.
        if ( SUCCEEDED ( SHGetFolderPathW ( NULL, CSIDL_APPDATA, NULL, 0, wpath ) ) )
        {
           widePathToOgreString ( mHomePath, wpath );
        }

        const DWORD dwAttrib = GetFileAttributes ( ( mHomePath + '\\' + subdir + '\\' ).c_str () ) ;

        const bool app_data_folder_exists = ( ( dwAttrib != INVALID_FILE_ATTRIBUTES ) &&
                                              ( dwAttrib & FILE_ATTRIBUTE_DIRECTORY ) ) ;

        if ( ! app_data_folder_exists )
        {
           const auto is_controlled_folder_access_enabled = [] ()
                                                              {
                                                                  const wchar_t* subKey    = L"SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access";
                                                                  const wchar_t* valueName = L"EnableControlledFolderAccess";

                                                                  DWORD value = 0 ;
                                                                  DWORD size  = sizeof ( value ) ;

                                                                  LSTATUS result = RegGetValueW ( HKEY_LOCAL_MACHINE,
                                                                                                  subKey,
                                                                                                  valueName,
                                                                                                  RRF_RT_REG_DWORD,
                                                                                                  nullptr,
                                                                                                  &value,
                                                                                                  &size ) ;

                                                                  if ( result == ERROR_SUCCESS )
                                                                  {
                                                                     return value == 1 ;
                                                                  }

                                                                  return false ;
                                                              } ;

           // The folder doesn't exist, so we can try to access the default Documents folder first,
           // and fallback to the APP_DATA folder otherwise.
           //
           // Do a basic check to see if we shouldn't even bother with the Document folder if 'Controlled Folder Access' is enabled
           bool can_use_documents = ! is_controlled_folder_access_enabled () ;

           // This call will cause the 'Controlled Folder Access' warning if it is enabled.
           if ( can_use_documents &&
                SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PERSONAL|CSIDL_FLAG_CREATE, NULL, 0, wpath)))
           {
               widePathToOgreString(mHomePath, wpath);
           }
           else
           {
              // Fallback to APP_DATA. We will then use this as the base folder from now-on.
           }
        }
        /////////////////////////////////////////////////////////////

#elif OGRE_PLATFORM == OGRE_PLATFORM_WINRT
        widePathToOgreString(mHomePath, Windows::Storage::ApplicationData::Current->LocalFolder->Path->Data());
#endif

        if(!mHomePath.empty())
        {
            //// create Ogre subdir
            //mHomePath += "\\Ogre\\";
            //if (!createDirectory(mHomePath))
            //{
            //    // couldn't create directory, fall back to current working dir
            //    mHomePath.clear();
            //}
            //else
            {
                mHomePath += '\\' + subdir + '\\';
                // create release subdir
                if (!createDirectory(mHomePath))
                {
                    // couldn't create directory, fall back to current working dir
                    mHomePath.clear();
                }
            }
        }
    }
    //---------------------------------------------------------------------
    bool FileSystemLayer::fileExists(const Ogre::String& path)
    {
        return _access(path.c_str(), 04) == 0; // Use CRT API rather than GetFileAttributesExA to pass Windows Store validation
    }
    //---------------------------------------------------------------------
    bool FileSystemLayer::createDirectory(const Ogre::String& path)
    {
        return !_mkdir(path.c_str()) || errno == EEXIST; // Use CRT API rather than CreateDirectoryA to pass Windows Store validation
    }
    //---------------------------------------------------------------------
    bool FileSystemLayer::removeDirectory(const Ogre::String& path)
    {
        return !_rmdir(path.c_str()) || errno == ENOENT; // Use CRT API to pass Windows Store validation
    }
    //---------------------------------------------------------------------
    bool FileSystemLayer::removeFile(const Ogre::String& path)
    {
        return !_unlink(path.c_str()) || errno == ENOENT; // Use CRT API to pass Windows Store validation
    }
    //---------------------------------------------------------------------
    bool FileSystemLayer::renameFile(const Ogre::String& oldname, const Ogre::String& newname)
    {
        if(fileExists(oldname) && fileExists(newname))
            removeFile(newname);
        return !rename(oldname.c_str(), newname.c_str()); // Use CRT API to pass Windows Store validation
    }
}
