/*
-----------------------------------------------------------------------------
This source file is part of OGRE-Next
(Object-oriented Graphics Rendering Engine)
For the latest info, see http://www.ogre3d.org/

Copyright (c) 2000-2023 Torus Knot Software Ltd

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

#ifndef OgreParticle2_H
#define OgreParticle2_H

#include "OgrePrerequisites.h"

#include "Math/Array/OgreArrayVector2.h"
#include "Math/Array/OgreArrayVector3.h"

#include "OgreHeaderPrefix.h"

namespace Ogre
{
    OGRE_ASSUME_NONNULL_BEGIN

    struct _OgreExport ParticleCpuData
    {
        /// Which of the packed values is ours. Value in range [0; 4) for SSE2
        uint8 mIndex;

        /// World position
        ArrayVector3 *RESTRICT_ALIAS mPosition;

        /// Direction (and speed)
        ArrayVector3 *RESTRICT_ALIAS mDirection;

        /// Width & Height
        ArrayVector2 *RESTRICT_ALIAS mDimensions;

        /// Current rotation value. MUST be kept in range [-PI; PI]
        ArrayRadian *RESTRICT_ALIAS mRotation;

        /// Speed of rotation in radians/sec
        ArrayRadian *RESTRICT_ALIAS mRotationSpeed;

        /// Time left to live, number of seconds left of particles natural life
        ArrayReal *RESTRICT_ALIAS mTimeToLive;

        /// Time to live, number of seconds left of particles natural life
        ArrayReal *RESTRICT_ALIAS mTotalTimeToLive;

        /// Current colour
        // ArrayVector4 *RESTRICT_ALIAS mColour;

        void advancePack( size_t numAdvance = 1u )
        {
            mPosition += numAdvance;
            mDirection += numAdvance;
            mDimensions += numAdvance;
            mRotation += numAdvance;
            mRotationSpeed += numAdvance;
            mTimeToLive += numAdvance;
            mTotalTimeToLive += numAdvance;
        }
    };

    struct _OgrePrivate ParticleGpuData
    {
        float mWidth;
        float mHeight;
        float mPos[3];
        int8  mDirection[3];
        // We use signed because SSE2 doesn't support unsigned.
        // Also when unpacking in vertex shader, we can pack it with mDirection's unpacking.
        // We lose one value of alpha though (because SNORM maps both -128 & -127 to -1)
        int8  mColourAlpha;
        int16 mRotation;
        int16 mColourRgb[3];
    };

    class _OgreExport Particle2
    {
    };

    OGRE_ASSUME_NONNULL_END
}  // namespace Ogre

#include "OgreHeaderSuffix.h"

#endif
