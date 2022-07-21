// ----------------------------------------------------------------------------
// <copyright file="Calculator.cs" company="Private">
// Copyright (c) 2022 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>07/21/2022 05:23:42 PM</date>
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

namespace SecretSharingDotNet.Math
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using System.Linq.Expressions;
    using System.Reflection;

    /// <summary>
    /// This class represents the calculator strategy pattern to decouple Shamir's Secret Sharing
    /// implementation from the concrete numeric data type like <see cref="System.Numerics.BigInteger"/>.
    /// </summary>
    public abstract class Calculator
    {
        /// <summary>
        /// Saves a dictionary of number data types derived from the <see cref="Calculator{TNumber}"/> class.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2104:DoNotDeclareReadOnlyMutableReferenceTypes")]
        protected static readonly ReadOnlyDictionary<Type, Type> ChildTypes = new ReadOnlyDictionary<Type, Type>(GetDerivedNumberTypes());

        /// <summary>
        /// Gets the number of elements of the byte representation of the <see cref="Calculator"/> object.
        /// </summary>
        public abstract int ByteCount { get; }

        /// <summary>
        /// Saves a dictionary of constructors of number data types derived from the <see cref="Calculator{TNumber}"/> class.
        /// </summary>
        protected static readonly ReadOnlyDictionary<Type, Func<byte[], Calculator>> ChildBaseCtors = new ReadOnlyDictionary<Type, Func<byte[], Calculator>>(GetDerivedCtors<byte[], Calculator>());

        /// <summary>
        /// Gets the byte representation of the <see cref="Calculator"/> object.
        /// </summary>
        public abstract ReadOnlyCollection<byte> ByteRepresentation { get; }

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is zero.
        /// </summary>
        public abstract bool IsZero { get; }

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is one.
        /// </summary>
        public abstract bool IsOne { get; }

        /// <summary>
        /// Gets a value indicating whether or not the current <see cref="Calculator"/> object is an even number.
        /// </summary>
        public abstract bool IsEven { get; }

        /// <summary>
        /// Gets a number that indicates the sign (negative, positive, or zero) of the current <see cref="Calculator"/> object.
        /// </summary>
        public abstract int Sign { get; }

        /// <summary>
        /// Creates a new instance derived from the <see cref="Calculator"/> class.
        /// </summary>
        /// <param name="data">byte array representation of the <paramref name="numberType"/></param>
        /// <param name="numberType">Type of number</param>
        /// <returns></returns>
        public static Calculator Create(byte[] data, Type numberType) => ChildBaseCtors[numberType](data);

        /// <summary>
        /// Returns a dictionary of constructors of number data types derived from the <see cref="Calculator"/> class.
        /// </summary>
        /// <returns></returns>
        protected static Dictionary<Type, Func<TParameter, TCalculator>> GetDerivedCtors<TParameter, TCalculator>() where TCalculator : Calculator
        {
            var res = new Dictionary<Type, Func<TParameter, TCalculator>>(ChildTypes.Count);
            var paramType = typeof(TParameter);
            var parameterExpression = Expression.Parameter(paramType);
            foreach (var childType in ChildTypes)
            {
                var ctorInfo = childType.Value.GetConstructor(new[] { paramType });
                var ctor = Expression.Lambda<Func<TParameter, TCalculator>>(Expression.New(ctorInfo, parameterExpression), parameterExpression)
                    .Compile();
                res.Add(childType.Key, ctor);
            }

            return res;
        }

        /// <summary>
        /// Returns a dictionary of number data types derived from the <see cref="Calculator"/> class.
        /// </summary>
        /// <returns></returns>
        /// <remarks>The key represents the integer data type of the derived calculator. The value represents the type of derived calculator.</remarks>
        private static Dictionary<Type, Type> GetDerivedNumberTypes()
        {
            var asm = Assembly.GetAssembly(typeof(Calculator));
            var listOfClasses = asm.GetTypes().Where(x => x.IsSubclassOf(typeof(Calculator)) && !x.IsGenericType);
            return listOfClasses.ToDictionary(x => x.BaseType?.GetGenericArguments()[0]);
        }
    }
}