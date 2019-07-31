/*
 * Copyright 2019 Leeds Beckett University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.qyouti.winselfcert;

/**
 * An exception which represents an error from the native Windows CAPI subsystem.
 * @author maber01
 */
public class WindowsCertificateException extends java.lang.Exception
{

    public WindowsCertificateException() {
        super();
    }

    public WindowsCertificateException(String message) {
        super(message);
    }

    public WindowsCertificateException(String message, Throwable cause) {
        super(message, cause);
    }

    public WindowsCertificateException(Throwable cause) {
        super(cause);
    }

    public WindowsCertificateException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
    
}
