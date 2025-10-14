try
    {
        try { Start-Transcript -Path "C:\Windows\Temp\WindowsActivation.Log" -Force -Append -ErrorAction Stop } catch {}

        Remove-Variable -Name OA3xOriginalProductKey -ErrorAction SilentlyContinue

        $OA3xOriginalProductKey = (gwmi -query 'select * from SoftwareLicensingService' -erroraction stop ).OA3xOriginalProductKey

        if($OA3xOriginalProductKey)
            {
                Write-Host "Product Key Successfully Retreived"

                # Display the output
                &cscript /nologo "$env:windir\System32\slmgr.vbs" -dlv

                # Check the activation Status
                &cscript.exe /nologo "$env:windir\System32\slmgr.vbs" -xpr

                # Remove any existing product key
                &cscript /nologo "$env:windir\System32\slmgr.vbs" -upk

                # Clear the product key
                &cscript /nologo "$env:windir\System32\slmgr.vbs" -cpky

                # Set the new product key retrieved from the hardware
                #&cscript /nologo "$env:windir\System32\slmgr.vbs" -ipk $OA3xOriginalProductKey

                # Activate the OS using the newly installed key
                #&cscript /nologo "$env:windir\System32\slmgr.vbs" -ato

                # Modern Activation
                changepk.exe /ProductKey $OA3xOriginalProductKey

                # Display the output
                &cscript.exe /nologo "$env:windir\System32\slmgr.vbs" -dlv

                # Check the activation Status
                &cscript.exe /nologo "$env:windir\System32\slmgr.vbs" -xpr
            }
        else
            {
                Write-Warning "No Product Key Retreived"
            }
    }
catch
    {
        throw $_
    }
finally
    {
        try { Stop-Transcript -ErrorAction Stop } catch {}
    }