package main

// probeAzure checks whether an Azure Blob Storage container exists and is
// publicly listable.
// TODO: implement the same pattern as probeAWS — GET
// https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
// 200 = exists + public; 404 = doesn't exist; 403/409 = exists, private.
// Note: Azure needs a storage *account* name too, not just a container name —
// your permutation strategy for Azure may need to vary account name as well
// as container name. Worth a design note in your README.
func probeAzure(bucketName string) *Finding {
	return nil
}
