import IconBtn from "./IconBtn"

export default function ConfirmationModal({ modalData }) {
    return (
        <div className="fixed inset-0 z-[1000] !mt-0 grid place-items-center overflow-auto bg-white bg-opacity-10 backdrop-blur-sm">
            <div className="w-11/12 max-w-[350px] rounded-lg border border-richblack-400 bg-richblack-800 p-6">
                <IconBtn
                    customClasses="bg-yellow-100 text-black rounded-md px-4 py-2 font-semibold "
                    onclick={modalData?.btn1Handler}
                    text={modalData?.btn1Text}
                />
                <button
                    className="cursor-pointer rounded-md bg-richblack-200 py-[8px] px-[20px] font-semibold text-richblack-900"
                    onClick={modalData?.btn2Handler}
                >
                    {modalData?.btn2Text}
                </button>
            </div>
        </div>
    )
}    