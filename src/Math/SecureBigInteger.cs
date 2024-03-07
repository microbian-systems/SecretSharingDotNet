// ----------------------------------------------------------------------------
// <copyright file="SecureBigInteger.cs" company="Private">
// Copyright (c) 2024 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/01/2024 07:34:00 PM</date>
// ----------------------------------------------------------------------------

#region License

// ----------------------------------------------------------------------------
// Copyright 2022 Sebastian Walther
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#endregion

#if NET6_0_OR_GREATER
namespace SecretSharingDotNet.Math;

using System;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// Represents a secure big integer.
/// </summary>
public class SecureBigInteger : IDisposable
{
    private readonly long length;
    private readonly unsafe uint* digitsPtr;
    private GCHandle digitsHandle;
    private bool disposed;

    private unsafe SecureBigInteger(uint* digits, GCHandle digitsHandle, long length)
    {
        this.digitsPtr = digits;
        this.length = length;
        this.digitsHandle = digitsHandle;
    }

    public unsafe SecureBigInteger(Span<byte> bytes)
    {
        uint[] digits = new uint[(bytes.Length + 3) / 4];
        this.digitsHandle = GCHandle.Alloc(digits, GCHandleType.Pinned);
        this.digitsPtr = (uint*)this.digitsHandle.AddrOfPinnedObject();
        this.length = digits.LongLength;
        for (int i = 0; i < bytes.Length; i++)
        {
            digits[i / 4] |= (uint)bytes[i] << i % 4 * 8;
        }
    }

    ~SecureBigInteger()
    {
        this.Dispose(false);
    }

    public unsafe SecureBigInteger Add1(SecureBigInteger other)
    {
        long maxLen = Math.Max(this.length, other.length);

        uint[] result = new uint[maxLen + 1];
        var digitsHandle1 = GCHandle.Alloc(result, GCHandleType.Pinned);

        long index = 0;
        ulong carry = 0;
        for (; index < other.length; ++index)
        {
            ulong sum = this.digitsPtr[index] + carry + other.digitsPtr[index];
            result[index] = (uint)sum;
            carry = sum >> 32;
        }

        for (; index < this.length; ++index)
        {
            ulong sum = this.digitsPtr[index] + carry;
            result[index] = (uint)sum;
            carry = sum >> 32;
        }

        result[index] = (uint)carry;

        uint* resultPtr = (uint*)digitsHandle1.AddrOfPinnedObject();
        return new SecureBigInteger(resultPtr, digitsHandle1, result.LongLength);
    }

    public unsafe SecureBigInteger Add2(SecureBigInteger other)
    {
        long maxLen = Math.Max(this.length, other.length);

        uint[] result = new uint[maxLen + 1];
        var digitsHandle1 = GCHandle.Alloc(result, GCHandleType.Pinned);
        ulong carry = 0;

        for (long index = 0; index < maxLen || carry != 0; ++index)
        {
            ulong sum = carry;
            if (index < this.length)
            {
                sum += this.digitsPtr[index];
            }

            if (index < other.length)
            {
                sum += other.digitsPtr[index];
            }

            carry = sum >> 32;
            result[index] = (uint)sum;
        }

        uint* resultPtr = (uint*)digitsHandle1.AddrOfPinnedObject();
        return new SecureBigInteger(resultPtr, digitsHandle1, result.LongLength);
    }

    public unsafe SecureBigInteger Subtract(SecureBigInteger other)
    {
        long maxLen = Math.Max(this.length, other.length);

        uint[] result = new uint[maxLen];
        var digitsHandle1 = GCHandle.Alloc(result, GCHandleType.Pinned);

        long index = 0;
        ulong borrow = 0;
        for (; index < other.length; ++index)
        {
            ulong diff = this.digitsPtr[index] - borrow - other.digitsPtr[index];
            result[index] = (uint)diff;
            borrow = diff >> 32 & 1;
        }

        for (; index < this.length; ++index)
        {
            ulong diff = this.digitsPtr[index] - borrow;
            result[index] = (uint)diff;
            borrow = diff >> 32 & 1;
        }

        if (borrow != 0)
        {
            throw new InvalidOperationException("Subtraction would result in a negative number.");
        }

        uint* resultPtr = (uint*)digitsHandle1.AddrOfPinnedObject();
        return new SecureBigInteger(resultPtr, digitsHandle1, result.LongLength);
    }

    public override unsafe string ToString()
    {
        var sb = new StringBuilder();
        for (long i = this.length - 1; i >= 0; i--)
        {
            string binary = Convert.ToString(this.digitsPtr[i], 2).PadLeft(32, '0');
            sb.Append(binary);
        }

        string binaryString = sb.ToString();
        string decimalString = BinaryToDecimal(binaryString);
        return decimalString;
    }

    private static string BinaryToDecimal(string binaryString)
    {
        string total = "0";
        for (int i = binaryString.Length - 1; i >= 0; i--)
        {
            if (binaryString[i] == '1')
            {
                total = AddStrings(total, PowerOfTwo(binaryString.Length - 1 - i));
            }
        }

        return total;
    }

    private static string AddStrings(string num1, string num2)
    {
        StringBuilder sb = new StringBuilder();
        int carry = 0;
        int i = num1.Length - 1;
        int j = num2.Length - 1;
        while (i >= 0 || j >= 0 || carry > 0)
        {
            int sum = carry;
            if (i >= 0)
            {
                sum += num1[i--] - '0';
            }

            if (j >= 0)
            {
                sum += num2[j--] - '0';
            }

            sb.Insert(0, sum % 10);
            carry = sum / 10;
        }

        return sb.ToString();
    }

    private static string PowerOfTwo(int power)
    {
        string result = "1";
        for (int i = 0; i < power; i++)
        {
            result = AddStrings(result, result);
        }

        return result;
    }

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    private unsafe void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            // Dispose managed resources.
        }

        for (int i = 0; i < this.length; i++)
        {
            this.digitsPtr[i] = 0;
        }

        this.digitsHandle.Free();
        this.digitsHandle = default;

        this.disposed = true;
    }
}
#endif