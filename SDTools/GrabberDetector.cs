namespace SDTools
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using dnlib.DotNet;

    public static class GrabberDetector
    {
        // Общий счётчик обнаружения
        public static int CountCalls = 0;

        // Список функций вызовов которые нужно найти
        private static readonly HashSet<string> Calls = new()
        {
            "BCrypt",
            "AesGcm",
            "AesGcmEx",
            "GetMasterKey",
            "DecryptWithKey",
            "cSQLite",
            "SQLite",
            "ZipStorer",
            "LoadLibrary",
            "GetDomainDetect",
            "LoadNSS",
            "SqliteEx",
            "GetModuleHandle",
            "BerkeleyDB",
            "PasswordCheck",
            "GetStackFiles",
            "Key4MagicNumber"
        };

        // Список функций импортов DllImport которые нужно найти
        private static readonly HashSet<string> Libs = new()
        {
            "CryptUnprotectData",
            "GetVersionEx",
            "IsClipboardFormatAvailable",
            "GetClipboardData",
            "BCryptDecrypt",
            "BCryptEncrypt",
            "GetModuleHandle",
            "SetDllDirectory",
        };



        /// <summary>
        /// Метод для поиска функций вызова в модуле
        /// </summary>
        /// <param name="module"></param>
        public static void GetCalls(ModuleDef module)
        {
            // Для показа на консоль разово
            int count = 1;
            foreach (string methods in Calls.SelectMany(methods => module.GetTypes().SelectMany(method => method.Methods.ToHashSet().Where(instr => instr.FullName.Contains(methods)).Select(instr => methods))).Distinct())
            {
                // Так как мы в цикле, убираем показ много раз
                if (count == 1)
                {
                    // Устанавливаем цвет текста
                    Console.ForegroundColor = ConsoleColor.DarkMagenta;
                    // Показываем на экран
                    Console.WriteLine("Найдены функции вызова");
                    count++; // Прибавляем счётчик, чтобы в след раз не выводило сообщение
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("\tФункция: ");
                Console.ForegroundColor = ConsoleColor.Cyan;     
                Console.WriteLine(methods);  // Выводим на экран функции которые нашли
                CountCalls++; // Прибавляем счётчик
                // Проверяем соотношение найденных элементов
                if (CountCalls >= 4)
                {
                    CountCalls = 60;
                }
                if (CountCalls >= 7)
                {
                    CountCalls = 95;
                }
                continue;
            }
        }

        public static void GetLibs(ModuleDef module)
        {
            int count = 1;
            foreach (string methods in Libs.SelectMany(methods => module.GetTypes().SelectMany(method => method.Methods.ToHashSet().Where(instr => instr.FullName.Contains(methods)).Select(instr => methods))).Distinct())
            {
                if (count == 1)
                {
                    Console.ForegroundColor = ConsoleColor.DarkMagenta;
                    Console.WriteLine("Найдены функции импортов");
                    count++;
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("\tИмпорт: ");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(methods);
                CountCalls++;
                continue;
            }
        }

        private static readonly HashSet<string> RunPEList = new()
        {
            "CreateProcess", "VirtualAllocEx",
        };

        public static void GetRunPE(ModuleDef module)
        {
            int count = 1;
            foreach (string methods in RunPEList.SelectMany(methods => module.GetTypes().SelectMany(method => method.Methods.ToHashSet().Where(instr => instr.FullName.Contains(methods)).Select(instr => methods))).Distinct())
            {
                if (count == 1)
                {
                    Console.ForegroundColor = ConsoleColor.DarkMagenta;
                    Console.WriteLine("Найден вызов RunPE - Запуск из памяти");
                    count++;
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("\tИмпорт: ");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(methods);
                CountCalls++;
                continue;
            }
        }
    }
}