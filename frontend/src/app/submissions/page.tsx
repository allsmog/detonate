import { SubmissionList } from "@/components/submission-list";

export default function SubmissionsPage() {
  return (
    <div className="mx-auto max-w-5xl py-8 px-4">
      <h1 className="mb-6 text-2xl font-bold">Submissions</h1>
      <SubmissionList />
    </div>
  );
}
