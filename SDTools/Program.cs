﻿namespace SDTools
{
    using System;
    using System.IO;
    using dnlib.DotNet;

    public static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {

            if (args.Length == 0)
            {
                Console.WriteLine("args not found");
                Console.ReadKey();
                return;
            }
            string ExePath = args[args.Length - 1];
            if (!File.Exists(ExePath))
            {
                Console.WriteLine("File doesn't exist!\nPath => {0}", ExePath);
                return;
            }
            try
            {
                using var Module = ModuleDefMD.Load(ExePath);
                GrabberDetector.GetCalls(Module);
                GrabberDetector.GetLibs(Module);
                GrabberDetector.GetRunPE(Module);
                Console.ResetColor();
                Console.WriteLine($"\r\n\r\n\tВероятность стилера: {GrabberDetector.CountCalls} %");
            }
            catch (BadImageFormatException)
            {
                Console.WriteLine("Only .Net Files");
            }
            Console.Read();
        }
    }
}